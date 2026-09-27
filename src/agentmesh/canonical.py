"""Canonical JSON (SPEC.md 5.3, RFC 8785).

Every signature on AgentMesh covers canonical JSON: object keys sorted by UTF-16
code units, no insignificant whitespace, numbers written the way ECMAScript
writes a double, strings with the minimal escaping ``JSON.stringify`` uses. The
TypeScript SDK gets this from JavaScript for free. Python has to spell each rule
out, because its own ``json`` module differs in all four places:

- ``sorted()`` compares code points, not UTF-16 code units, so a key above
  U+FFFF sorts after ``"\\uffff"`` in Python and before it in JavaScript;
- ``repr(1e-07)`` is ``1e-07`` where JavaScript writes ``1e-7``, ``1e20`` is
  ``1e+20`` where JavaScript writes ``100000000000000000000``, and a Python
  ``int`` has no ceiling where JavaScript rounds to a double;
- ``json.dumps`` writes ``NaN`` (not JSON at all) where JavaScript writes ``null``;
- a lone surrogate cannot be encoded to UTF-8 by Python, where JavaScript
  escapes it as ``\\udXXX``.

Absent and null are different things (SPEC 5.3): a key that is not in the dict
is absent and is not written; a key whose value is ``None`` is written as
``null``. Build envelopes by leaving keys out, never by setting them to None.

The conformance fixture ``conformance/canonical-json.json`` and the vectors in
``tests/vectors/ts-sdk-vectors.json`` hold this module to the TypeScript bytes.
"""

from __future__ import annotations

import json
import math
from typing import Any

__all__ = ["canonical_json", "canonical_bytes", "js_number", "js_string", "parse_json"]


def js_number(value: float | int) -> str:
    """Format a number exactly as ECMAScript ``Number::toString`` does.

    Integers are first rounded to the nearest double, as JavaScript would when
    it parsed them. NaN and the infinities become ``null``, as ``JSON.stringify``
    writes them.
    """
    if isinstance(value, bool):  # bool is an int subclass; never a number here
        raise TypeError("a bool is not a number")
    try:
        x = float(value)
    except OverflowError:
        return "null"
    if math.isnan(x) or math.isinf(x):
        return "null"
    if x == 0:
        return "0"  # includes negative zero: the sign is dropped
    if x < 0:
        return "-" + js_number(-x)

    # repr() gives the shortest digit string that round-trips, which is the
    # digit string ECMAScript picks too. Pull out digits and exponent.
    r = repr(x)
    mantissa, _, exp_text = r.partition("e")
    exp = int(exp_text) if exp_text else 0
    if "." in mantissa:
        int_part, frac_part = mantissa.split(".")
    else:
        int_part, frac_part = mantissa, ""
    digits = (int_part + frac_part).lstrip("0")
    # value == int(digits) * 10 ** (exp - len(frac_part)) once leading zeros go
    scale = exp - len(frac_part)
    stripped = digits.rstrip("0")
    scale += len(digits) - len(stripped)
    digits = stripped
    k = len(digits)
    n = k + scale  # value == 0.digits * 10 ** n

    if k <= n <= 21:
        return digits + "0" * (n - k)
    if 0 < n <= 21:
        return digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + digits
    e = n - 1
    sign = "+" if e >= 0 else "-"
    if k == 1:
        return f"{digits}e{sign}{abs(e)}"
    return f"{digits[0]}.{digits[1:]}e{sign}{abs(e)}"


_ESCAPES = {
    0x22: '\\"',
    0x5C: "\\\\",
    0x08: "\\b",
    0x0C: "\\f",
    0x0A: "\\n",
    0x0D: "\\r",
    0x09: "\\t",
}


def _utf16_units(s: str) -> list[int]:
    """The UTF-16 code units of ``s``. A lone surrogate stays one unit."""
    units: list[int] = []
    for ch in s:
        cp = ord(ch)
        if cp >= 0x10000:
            cp -= 0x10000
            units.append(0xD800 | (cp >> 10))
            units.append(0xDC00 | (cp & 0x3FF))
        else:
            units.append(cp)
    return units


def js_string(s: str) -> str:
    """Quote a string exactly as ``JSON.stringify`` does (well-formed variant).

    Works on UTF-16 code units so that a surrogate pair held as two Python
    characters is written as the character it encodes, and a lone surrogate is
    escaped rather than breaking UTF-8 encoding later.
    """
    units = _utf16_units(s)
    out: list[str] = ['"']
    i = 0
    n = len(units)
    while i < n:
        u = units[i]
        if u in _ESCAPES:
            out.append(_ESCAPES[u])
        elif u < 0x20:
            out.append(f"\\u{u:04x}")
        elif 0xD800 <= u <= 0xDBFF:
            if i + 1 < n and 0xDC00 <= units[i + 1] <= 0xDFFF:
                cp = 0x10000 + ((u - 0xD800) << 10) + (units[i + 1] - 0xDC00)
                out.append(chr(cp))
                i += 1
            else:
                out.append(f"\\u{u:04x}")
        elif 0xDC00 <= u <= 0xDFFF:
            out.append(f"\\u{u:04x}")
        else:
            out.append(chr(u))
        i += 1
    out.append('"')
    return "".join(out)


def _key_order(key: str) -> list[int]:
    return _utf16_units(key)


def canonical_json(value: Any) -> str:
    """Deterministic JSON text for signing (SPEC 5.3)."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return js_number(value)
    if isinstance(value, str):
        return js_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_json(v) for v in value) + "]"
    if isinstance(value, dict):
        for k in value:
            if not isinstance(k, str):
                raise TypeError(f"canonical JSON object keys must be strings, got {type(k).__name__}")
        keys = sorted(value.keys(), key=_key_order)
        return "{" + ",".join(js_string(k) + ":" + canonical_json(value[k]) for k in keys) + "}"
    raise TypeError(f"{type(value).__name__} is not JSON: convert it to a dict, list, str, number, bool or None first")


def canonical_bytes(value: Any) -> bytes:
    """UTF-8 bytes of :func:`canonical_json`. Lone surrogates are already escaped."""
    return canonical_json(value).encode("utf-8")


def _refuse_constant(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")


def parse_json(data: bytes | str) -> Any:
    """Parse JSON the way a JavaScript peer does: strict about NaN/Infinity.

    Python's parser otherwise accepts ``NaN`` and ``Infinity``, which no
    JavaScript peer would ever produce and which cannot be signed consistently.
    """
    if isinstance(data, (bytes, bytearray, memoryview)):
        data = bytes(data).decode("utf-8", errors="surrogatepass")
    return json.loads(data, parse_constant=_refuse_constant)
