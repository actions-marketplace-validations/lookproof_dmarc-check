from __future__ import annotations

import base64

import pytest

from dmarc_check.checks.dkim import check_dkim, rsa_key_bits
from dmarc_check.findings import Severity

from .conftest import ids


def _der(tag: int, body: bytes) -> bytes:
    n = len(body)
    if n < 0x80:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + body


def _int(value: int) -> bytes:
    raw = value.to_bytes((value.bit_length() + 8) // 8, "big")  # leading 0 keeps it positive
    return _der(0x02, raw)


def rsa_pkcs1(bits: int) -> bytes:
    modulus = (1 << (bits - 1)) | 1
    return _der(0x30, _int(modulus) + _int(65537))


def rsa_spki(bits: int) -> bytes:
    alg = _der(0x30, _der(0x06, bytes.fromhex("2a864886f70d010101")) + b"\x05\x00")
    return _der(0x30, alg + _der(0x03, b"\x00" + rsa_pkcs1(bits)))


def key_record(bits: int, spki: bool = True, extra: str = "") -> str:
    der = rsa_spki(bits) if spki else rsa_pkcs1(bits)
    return f"v=DKIM1; k=rsa;{extra} p={base64.b64encode(der).decode()}"


@pytest.mark.parametrize("bits", [512, 1024, 2048, 4096])
def test_rsa_key_bits(bits: int) -> None:
    assert rsa_key_bits(rsa_spki(bits)) == bits
    assert rsa_key_bits(rsa_pkcs1(bits)) == bits


def run(dns, make_ctx, *records: str, selector: str = "s1"):
    dns.txt_records[f"{selector}._domainkey.example.com"] = list(records)
    ctx = make_ctx(selectors=[selector])
    check_dkim(ctx)
    return ctx


def test_no_selectors_no_queries(dns, make_ctx) -> None:
    ctx = make_ctx()
    check_dkim(ctx)
    assert ids(ctx) == []
    assert dns.queries == []


def test_2048_ok(dns, make_ctx) -> None:
    assert ids(run(dns, make_ctx, key_record(2048))) == []


def test_split_key_with_whitespace(dns, make_ctx) -> None:
    record = key_record(2048)
    assert ids(run(dns, make_ctx, record[:60] + " " + record[60:])) == []


def test_pkcs1_key_ok(dns, make_ctx) -> None:
    assert ids(run(dns, make_ctx, key_record(4096, spki=False))) == []


def test_1024_warns(dns, make_ctx) -> None:
    ctx = run(dns, make_ctx, key_record(1024))
    assert ids(ctx) == ["dkim-weak-key"]
    assert ctx.findings[0].severity is Severity.WARN


def test_under_1024_errors(dns, make_ctx) -> None:
    ctx = run(dns, make_ctx, key_record(768))
    assert ids(ctx) == ["dkim-key-too-short"]
    assert ctx.findings[0].severity is Severity.ERROR
    assert ctx.findings[0].url.endswith("/dkim-weak-key")


def test_not_found(dns, make_ctx) -> None:
    ctx = make_ctx(selectors=["missing"])
    check_dkim(ctx)
    assert ids(ctx) == ["dkim-not-found"]


def test_txt_without_key_is_not_found(dns, make_ctx) -> None:
    assert ids(run(dns, make_ctx, "hello")) == ["dkim-not-found"]


def test_multiple(dns, make_ctx) -> None:
    assert ids(run(dns, make_ctx, key_record(2048), key_record(2048))) == ["dkim-multiple-records"]


def test_revoked(dns, make_ctx) -> None:
    assert ids(run(dns, make_ctx, "v=DKIM1; k=rsa; p=")) == ["dkim-key-revoked"]


@pytest.mark.parametrize(
    "record",
    [
        "v=DKIM1; p=not*base64",
        "v=DKIM1; p=" + base64.b64encode(b"\x30\x03\x02\x01").decode(),
        "v=DKIM1; k=dsa; p=" + base64.b64encode(b"abc").decode(),
        "v=DKIM1; k=ed25519; p=" + base64.b64encode(b"short").decode(),
        "v=DKIM1; p=" + base64.b64encode(b"\x04\x00").decode(),
    ],
)
def test_invalid_key(dns, make_ctx, record: str) -> None:
    assert ids(run(dns, make_ctx, record)) == ["dkim-invalid-key"]


def test_ed25519_ok(dns, make_ctx) -> None:
    record = "v=DKIM1; k=ed25519; p=" + base64.b64encode(bytes(32)).decode()
    assert ids(run(dns, make_ctx, record)) == []


@pytest.mark.parametrize("prefix", ["v=DKIM2; ", "k=rsa; v=DKIM1; ", "junk; "])
def test_syntax_error(dns, make_ctx, prefix: str) -> None:
    record = prefix + "p=" + base64.b64encode(rsa_spki(2048)).decode()
    assert ids(run(dns, make_ctx, record)) == ["dkim-syntax-error"]


def test_testing_mode(dns, make_ctx) -> None:
    assert ids(run(dns, make_ctx, key_record(2048, extra=" t=y:s;"))) == ["dkim-testing-mode"]


def test_several_selectors(dns, make_ctx) -> None:
    dns.txt_records["a._domainkey.example.com"] = [key_record(2048)]
    dns.txt_records["b._domainkey.example.com"] = [key_record(1024)]
    ctx = make_ctx(selectors=["a", "b", "c"])
    check_dkim(ctx)
    assert ids(ctx) == ["dkim-weak-key", "dkim-not-found"]
