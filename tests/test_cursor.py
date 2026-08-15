"""Tests for the bit-level read cursor."""

from __future__ import annotations

import struct

import pytest

from kober.cursor import Cursor
from kober.errors import TruncatedRead
from kober.spec import Endian


def test_starts_at_zero():
    cursor = Cursor(b"\x01\x02")
    assert cursor.tell() == 0
    assert cursor.is_aligned()
    assert cursor.remaining_bits() == 16
    assert cursor.remaining_bytes() == 2
    assert not cursor.at_end()


# --- whole-byte reads ------------------------------------------------------


def test_big_endian_is_the_default():
    assert Cursor(b"\x12\x34").read_int(16) == 0x1234


def test_little_endian():
    assert Cursor(b"\x12\x34").read_int(16, endian=Endian.LITTLE) == 0x3412


def test_signed():
    assert Cursor(b"\xff\xff").read_int(16, signed=True) == -1
    assert Cursor(b"\x80\x00").read_int(16, signed=True) == -32768
    assert Cursor(b"\x7f\xff").read_int(16, signed=True) == 32767


def test_unsigned_reads_the_same_bytes_differently():
    assert Cursor(b"\xff\xff").read_int(16) == 65535


def test_sequential_reads_advance():
    cursor = Cursor(struct.pack(">HHH", 1, 2, 3))
    assert [cursor.read_int(16) for _ in range(3)] == [1, 2, 3]
    assert cursor.at_end()


def test_read_bytes():
    cursor = Cursor(b"abcdef")
    assert cursor.read_bytes(3) == b"abc"
    assert cursor.read_bytes(3) == b"def"


def test_read_remaining():
    cursor = Cursor(b"abcdef")
    cursor.read_bytes(2)
    assert cursor.read_remaining() == b"cdef"
    assert cursor.at_end()


def test_zero_width_reads_are_legal():
    cursor = Cursor(b"ab")
    assert cursor.read_bytes(0) == b""
    assert cursor.read_bits(0) == 0
    assert cursor.tell() == 0


# --- sub-byte reads --------------------------------------------------------


def test_bits_are_most_significant_first():
    cursor = Cursor(bytes([0b10110000]))
    assert cursor.read_bits(1) == 1
    assert cursor.read_bits(1) == 0
    assert cursor.read_bits(2) == 0b11
    assert cursor.tell() == 4


def test_bits_across_a_byte_boundary():
    cursor = Cursor(bytes([0b00000001, 0b10000000]))
    cursor.read_bits(7)
    assert cursor.read_bits(2) == 0b11


def test_the_dns_flags_word():
    """The case field granularity exists for: qr, opcode packed in two bytes."""
    cursor = Cursor(struct.pack(">H", 0x8180))
    assert cursor.read_bits(1) == 1  # qr
    assert cursor.read_bits(4) == 0  # opcode
    assert cursor.read_bits(1) == 0  # aa
    assert cursor.read_bits(1) == 0  # tc
    assert cursor.read_bits(1) == 1  # rd


def test_signed_sub_byte():
    cursor = Cursor(bytes([0b11110000]))
    assert cursor.read_int(4, signed=True) == -1


def test_endian_is_ignored_below_a_byte():
    """Byte order is not a property a four-bit field has."""
    big = Cursor(bytes([0b10100000])).read_int(4, endian=Endian.BIG)
    little = Cursor(bytes([0b10100000])).read_int(4, endian=Endian.LITTLE)
    assert big == little == 0b1010


def test_unaligned_multibyte_read_takes_bits_not_bytes():
    cursor = Cursor(bytes([0b00001111, 0b11110000]))
    cursor.read_bits(4)
    assert cursor.read_int(8) == 0b11111111


# --- spans cite containing bytes ------------------------------------------


def test_span_of_a_whole_byte_read():
    cursor = Cursor(b"\x12\x34\x56")
    mark = cursor.tell()
    cursor.read_int(16)
    assert cursor.span(mark) == (0, 2)


def test_span_of_a_sub_byte_read_rounds_outward():
    """A four-bit field cites the byte containing it — DESIGN.md §1."""
    cursor = Cursor(b"\xab")
    mark = cursor.tell()
    cursor.read_bits(4)
    assert cursor.span(mark) == (0, 1)


def test_overlapping_spans_are_the_normal_case():
    """The flags word and the bits inside it all cite the same range."""
    data = struct.pack(">H", 0x8180)
    word = Cursor(data)
    mark = word.tell()
    word.read_int(16)
    whole = word.span(mark)

    bits = Cursor(data)
    mark = bits.tell()
    bits.read_bits(1)
    qr = bits.span(mark)
    mark = bits.tell()
    bits.read_bits(4)
    opcode = bits.span(mark)

    assert whole == (0, 2)
    assert qr == (0, 1)
    assert opcode == (0, 1)


def test_span_with_a_base_is_absolute():
    """Runs are relative; citations are not."""
    cursor = Cursor(b"\x12\x34", base=100)
    mark = cursor.tell()
    cursor.read_int(16)
    assert cursor.span(mark) == (100, 102)
    assert cursor.byte_offset() == 102


def test_span_of_a_zero_width_read_is_empty_not_negative():
    cursor = Cursor(b"ab")
    assert cursor.span(cursor.tell()) == (0, 0)


def test_span_arguments_may_arrive_either_way_round():
    cursor = Cursor(b"\x12\x34")
    cursor.read_int(16)
    assert cursor.span(0) == (0, 2)


# --- truncation ------------------------------------------------------------


def test_reading_past_the_end_is_truncation():
    cursor = Cursor(b"\x12")
    with pytest.raises(TruncatedRead, match="runs past the end"):
        cursor.read_int(16)


def test_truncation_names_the_offset():
    cursor = Cursor(b"\x12\x34\x56", base=50)
    cursor.read_int(16)
    with pytest.raises(TruncatedRead, match="offset 52"):
        cursor.read_int(16)


def test_reading_more_bytes_than_remain():
    with pytest.raises(TruncatedRead):
        Cursor(b"abc").read_bytes(4)


def test_bit_read_past_the_end():
    cursor = Cursor(b"\xff")
    cursor.read_bits(6)
    with pytest.raises(TruncatedRead):
        cursor.read_bits(4)


# --- alignment -------------------------------------------------------------


def test_byte_reads_refuse_an_unaligned_position():
    """Auto-aligning would drop bits silently, which is what §2 forbids."""
    cursor = Cursor(b"\xff\xff")
    cursor.read_bits(4)
    with pytest.raises(ValueError, match="do not add up to a whole number of bytes"):
        cursor.read_bytes(1)


def test_align_reports_what_it_skipped():
    cursor = Cursor(b"\xff\xff")
    cursor.read_bits(4)
    assert cursor.align() == 4
    assert cursor.is_aligned()


def test_align_when_already_aligned_is_a_no_op():
    cursor = Cursor(b"\xff")
    assert cursor.align() == 0
    assert cursor.tell() == 0


def test_find_refuses_an_unaligned_position():
    cursor = Cursor(b"abc\x00")
    cursor.read_bits(4)
    with pytest.raises(ValueError, match="inside a byte"):
        cursor.find(b"\x00")


# --- seeking and searching -------------------------------------------------


def test_seek():
    cursor = Cursor(b"\x12\x34")
    cursor.seek(8)
    assert cursor.read_int(8) == 0x34


def test_seek_outside_the_run():
    cursor = Cursor(b"\x12")
    with pytest.raises(ValueError, match="outside the run"):
        cursor.seek(9)


def test_find_a_delimiter():
    cursor = Cursor(b"host\x00rest")
    assert cursor.find(b"\x00") == 4


def test_find_is_relative_to_the_position():
    cursor = Cursor(b"aa\x00bb\x00")
    cursor.read_bytes(3)
    assert cursor.find(b"\x00") == 2


def test_find_does_not_move_the_position():
    cursor = Cursor(b"host\x00")
    cursor.find(b"\x00")
    assert cursor.tell() == 0


def test_find_missing_delimiter():
    assert Cursor(b"no terminator here").find(b"\x00") is None


def test_find_refuses_an_empty_delimiter():
    with pytest.raises(ValueError, match="empty delimiter"):
        Cursor(b"abc").find(b"")


# --- negative counts -------------------------------------------------------


def test_negative_counts_are_refused():
    with pytest.raises(ValueError, match="negative"):
        Cursor(b"abc").read_bytes(-1)
    with pytest.raises(ValueError, match="negative"):
        Cursor(b"abc").read_bits(-1)
