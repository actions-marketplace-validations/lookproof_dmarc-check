"""DKIM key records (RFC 6376) for the selectors the user names."""

from __future__ import annotations

import base64
import binascii

from ..findings import Severity
from . import Context, parse_tags

CHECK = "dkim"
WEAK_BITS = 2048
MIN_BITS = 1024
_RSA_OID = bytes.fromhex("2a864886f70d010101")  # 1.2.840.113549.1.1.1


class _DerError(ValueError):
    pass


def _tlv(data: bytes, pos: int) -> tuple[int, int, int]:
    """Return (tag, value_start, value_end) for the DER element at ``pos``."""
    if pos + 2 > len(data):
        raise _DerError("truncated")
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or pos + n > len(data):
            raise _DerError("bad length")
        length = int.from_bytes(data[pos : pos + n], "big")
        pos += n
    if pos + length > len(data):
        raise _DerError("truncated")
    return tag, pos, pos + length


def _rsa_modulus_bits(rsa_public_key: bytes) -> int:
    """Bits of the modulus in a PKCS#1 RSAPublicKey SEQUENCE { n, e }."""
    tag, start, _ = _tlv(rsa_public_key, 0)
    if tag != 0x30:
        raise _DerError("not a sequence")
    tag, nstart, nend = _tlv(rsa_public_key, start)
    if tag != 0x02:
        raise _DerError("modulus is not an integer")
    return int.from_bytes(rsa_public_key[nstart:nend], "big").bit_length()


def rsa_key_bits(der: bytes) -> int:
    """Return the RSA modulus size of a SubjectPublicKeyInfo or bare RSAPublicKey."""
    tag, start, _ = _tlv(der, 0)
    if tag != 0x30:
        raise _DerError("not a sequence")
    inner_tag, istart, iend = _tlv(der, start)
    if inner_tag == 0x02:
        return _rsa_modulus_bits(der)  # PKCS#1 RSAPublicKey
    if inner_tag != 0x30:
        raise _DerError("unexpected structure")
    oid_tag, ostart, oend = _tlv(der, istart)
    if oid_tag != 0x06 or der[ostart:oend] != _RSA_OID:
        raise _DerError("not an RSA key")
    bit_tag, bstart, bend = _tlv(der, iend)
    if bit_tag != 0x03 or bstart >= bend or der[bstart] != 0:
        raise _DerError("bad bit string")
    return _rsa_modulus_bits(der[bstart + 1 : bend])


def check_dkim(ctx: Context) -> None:
    for selector in ctx.dkim_selectors:
        _check_selector(ctx, selector)


def _check_selector(ctx: Context, selector: str) -> None:
    name = f"{selector}._domainkey.{ctx.domain}"
    ans = ctx.resolver.txt(name)
    records = [t for t in ans.records if "p=" in t.replace(" ", "")]
    if not records:
        ctx.add(CHECK, "dkim-not-found", Severity.ERROR, f"No DKIM key at {name}")
        return
    if len(records) > 1:
        ctx.add(
            CHECK,
            "dkim-multiple-records",
            Severity.ERROR,
            f"{len(records)} DKIM key records at {name}; verification is unpredictable",
        )
        return
    tags, bad = parse_tags(records[0])
    values = {k.lower(): v for k, v in tags}
    problems = [f"malformed tag {b!r}" for b in bad]
    if "v" in values and (tags[0][0].lower() != "v" or values["v"] != "DKIM1"):
        problems.append("v= must be DKIM1 and come first")
    if problems:
        ctx.add(
            CHECK,
            "dkim-syntax-error",
            Severity.ERROR,
            f"DKIM record for selector {selector} is invalid: " + "; ".join(problems),
        )
        return

    if "y" in [f.strip().lower() for f in values.get("t", "").split(":")]:
        ctx.add(
            CHECK,
            "dkim-testing-mode",
            Severity.INFO,
            f"Selector {selector} has t=y (testing): receivers may ignore failures",
        )

    p = "".join(values.get("p", "").split())
    if not p:
        ctx.add(
            CHECK,
            "dkim-key-revoked",
            Severity.WARN,
            f"Selector {selector} has an empty p= (key revoked)",
        )
        return
    try:
        der = base64.b64decode(p, validate=True)
    except (binascii.Error, ValueError):
        ctx.add(CHECK, "dkim-invalid-key", Severity.ERROR, f"Selector {selector}: p= is not valid base64")
        return

    key_type = values.get("k", "rsa").lower()
    if key_type == "ed25519":
        if len(der) != 32:
            ctx.add(
                CHECK,
                "dkim-invalid-key",
                Severity.ERROR,
                f"Selector {selector}: Ed25519 key must be 32 bytes, got {len(der)}",
            )
        return
    if key_type != "rsa":
        ctx.add(CHECK, "dkim-invalid-key", Severity.ERROR, f"Selector {selector}: unknown key type k={key_type}")
        return
    try:
        bits = rsa_key_bits(der)
    except _DerError as exc:
        ctx.add(
            CHECK,
            "dkim-invalid-key",
            Severity.ERROR,
            f"Selector {selector}: RSA key could not be parsed ({exc})",
        )
        return
    if bits < MIN_BITS:
        ctx.add(
            CHECK,
            "dkim-key-too-short",
            Severity.ERROR,
            f"Selector {selector}: {bits}-bit RSA key; receivers reject keys under {MIN_BITS} bits",
        )
    elif bits < WEAK_BITS:
        ctx.add(
            CHECK,
            "dkim-weak-key",
            Severity.WARN,
            f"Selector {selector}: {bits}-bit RSA key; use {WEAK_BITS} bits",
        )
