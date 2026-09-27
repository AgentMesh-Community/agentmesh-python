"""Canonical JSON: held to conformance/canonical-json.json and to vectors the
TypeScript SDK produced (tests/vectors/ts-sdk-vectors.json)."""

import struct

import pytest

from agentmesh.canonical import canonical_json, js_number, js_string, parse_json

from .conftest import load

FIXTURE = load("conformance/canonical-json.json")
TS = load("ts-sdk-vectors.json")


@pytest.mark.parametrize("v", FIXTURE["vectors"], ids=lambda v: v["name"])
def test_conformance_fixture(v):
    assert canonical_json(parse_json(v["input_json"])) == v["canonical"]


@pytest.mark.parametrize("row", FIXTURE["number_bits"], ids=lambda r: r["ieee754_hex"])
def test_number_bits(row):
    x = struct.unpack(">d", bytes.fromhex(row["ieee754_hex"]))[0]
    expected = row["canonical"]
    got = js_number(x)
    if expected is None or row.get("error"):
        assert got == "null"  # NaN / Infinity: JSON.stringify writes null
    else:
        assert got == expected


@pytest.mark.parametrize("v", TS["canonical"], ids=lambda v: v["name"])
def test_matches_typescript(v):
    assert canonical_json(parse_json(v["input_json"])) == v["canonical"]


def test_absent_is_not_null():
    assert canonical_json({"a": None}) == '{"a":null}'
    assert canonical_json({}) == "{}"


def test_surrogate_pair_held_as_two_chars_is_one_character():
    assert js_string("😀") == '"\U0001F600"'


def test_nan_and_infinity_are_null():
    assert canonical_json([float("nan"), float("inf"), -float("inf")]) == "[null,null,null]"


def test_huge_int_beyond_double_is_null():
    assert canonical_json(10**400) == "null"


def test_bool_is_not_a_number():
    assert canonical_json([True, False, 1, 0]) == "[true,false,1,0]"


def test_non_json_types_are_refused():
    with pytest.raises(TypeError):
        canonical_json({"when": object()})
    with pytest.raises(TypeError):
        canonical_json({1: "x"})


def test_parse_refuses_nan():
    with pytest.raises(ValueError):
        parse_json("[NaN]")
