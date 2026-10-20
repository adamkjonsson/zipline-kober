"""Every example's ``example.json``: the description the tests and the pipeline share."""

from __future__ import annotations

import json
from pathlib import Path

import examplekit
import pytest
from examplekit import Example, discover

DESCRIBED = discover()


def test_the_examples_that_bring_their_own_code_describe_themselves():
    assert "wireguard" in [example.name for example in DESCRIBED]


@pytest.mark.parametrize("example", DESCRIBED, ids=lambda example: example.name)
def test_a_description_names_files_that_exist(example: Example):
    named = [example.spec, example.transforms, example.tunnel, example.inside]
    for file in filter(None, named):
        assert example.path(file).is_file(), file
    for arg in example.inner_traffic():
        assert "{folder}" not in arg


@pytest.mark.parametrize("example", DESCRIBED, ids=lambda example: example.name)
def test_a_description_says_what_the_spec_says(example: Example):
    """The failure and the key parameter are the spec's own, not a copy that drifted."""
    spec = example.model()
    assert example.failure in {decl.fails_as for decl in spec.transforms.values()}
    if example.keys is not None:
        assert example.keys in [param.name for param in spec.params]
    if example.tunnel is not None:
        assert example.port is not None, "a tunnel needs a port"
    if example.inputs:
        assert example.tunnel is not None, "the pipeline generates inputs through a tunnel"


def test_a_key_the_kit_does_not_know_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A misspelt key would otherwise be a default the writer never chose."""
    (tmp_path / "mine").mkdir()
    description = {
        "spec": "mine.yaml", "transforms": "mine.py", "packet_role": "mine.packet",
        "packet_label": "dec:mine", "failure": "inflate-failed", "tunel": "seal.py",
    }
    (tmp_path / "mine" / "example.json").write_text(json.dumps(description))
    monkeypatch.setattr(examplekit, "EXAMPLES", tmp_path)
    with pytest.raises(ValueError, match="unknown keys \\['tunel'\\]"):
        Example.load("mine")


def test_hex_and_lists_are_read_into_their_types(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    (tmp_path / "mine").mkdir()
    description = {
        "spec": "mine.yaml", "transforms": "mine.py", "packet_role": "mine.packet",
        "packet_label": "dec:mine", "failure": "inflate-failed",
        "packet_prefix": "0a0b", "traffic": ["--messages", "{folder}/m.json"],
        "inputs": {"mine_loss": ["--tunnel-packet-loss", "0.1"]},
    }
    (tmp_path / "mine" / "example.json").write_text(json.dumps(description))
    monkeypatch.setattr(examplekit, "EXAMPLES", tmp_path)
    example = Example.load("mine")
    assert example.carries_packet(b"\x0a\x0b\x01")
    assert not example.carries_packet(b"\x0a\x01")
    assert example.inner_traffic() == ["--messages", f"{tmp_path / 'mine'}/m.json"]
    assert example.inputs == {"mine_loss": ("--tunnel-packet-loss", "0.1")}
