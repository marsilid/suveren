"""The own site mode: the ownership proof and the checks that need it (offline)."""

import asyncio
import base64

import httpx
import pytest

from suveren import ownership
from suveren.checks import Status
from suveren.dnsutil import DnsLookupError
from suveren.ownsite import (
    DeepTls,
    MxTransport,
    collect_mail_transport,
    deep_tls_check,
    describe_key,
    exposed_files_check,
    looks_like,
    mail_transport_check,
)


@pytest.fixture(autouse=True)
def cache(tmp_path, monkeypatch):
    monkeypatch.setenv("SUVEREN_CACHE", str(tmp_path))


class Resolver:
    kind = "fake"

    def __init__(self, records):
        self.records = records

    async def resolve(self, name, rtype):
        value = self.records.get((name, rtype), [])
        if value == ["SERVFAIL"]:
            raise DnsLookupError("SERVFAIL")
        return value


def client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def run(coro):
    return asyncio.run(coro)


# --- ownership ------------------------------------------------------------------------


def test_token_is_kept_and_private_to_the_domain():
    a = ownership.token_for("a.ru")
    assert a == ownership.token_for("a.ru") and a != ownership.token_for("b.ru")
    assert len(a) == 32
    text = ownership.instructions("a.ru")
    assert f'"suveren-verify={a}"' in text and "/.well-known/suveren-verify.txt" in text


def test_ownership_by_txt_or_file_and_refused_otherwise():
    token = ownership.token_for("a.ru")
    by_txt = Resolver({("_suveren-verify.a.ru", "TXT"): [f"suveren-verify={token}"]})

    async def go(resolver, handler):
        async with client(handler) as c:
            return await ownership.verify(resolver, c, "a.ru")

    proof = run(go(by_txt, lambda r: httpx.Response(404)))
    assert proof.ok and "TXT" in proof.how
    by_file = run(go(Resolver({}), lambda r: httpx.Response(200, text=token + "\n")))
    assert by_file.ok and "файл" in by_file.how
    wrong = run(go(Resolver({}), lambda r: httpx.Response(200, text="other")))
    assert not wrong.ok

    def down(request):
        raise httpx.ConnectError("no", request=request)

    assert not run(go(Resolver({("_suveren-verify.a.ru", "TXT"): ["SERVFAIL"]}), down)).ok


def test_broken_token_file_is_replaced(tmp_path):
    path = tmp_path / "ownership" / "a.ru.json"
    path.parent.mkdir(parents=True)
    path.write_text('{"token": "not-hex"}', "utf-8")
    assert len(ownership.token_for("a.ru")) == 32


def test_verify_command_without_proof_explains(monkeypatch):
    from typer.testing import CliRunner

    from suveren.cli import app

    async def refused(host, timeout):
        return ownership.Proof(False, "ни TXT-записи, ни файла")

    monkeypatch.setattr("suveren.cli._prove_ownership", refused)
    result = CliRunner().invoke(app, ["verify", "a.ru"])
    assert result.exit_code == 4 and "_suveren-verify.a.ru" in result.output
    scan = CliRunner().invoke(app, ["scan", "a.ru", "--own-site", "--no-report"])
    assert scan.exit_code == 2 and "не подтверждено" in scan.output

    async def proved(host, timeout):
        return ownership.Proof(True, "TXT-запись")

    monkeypatch.setattr("suveren.cli._prove_ownership", proved)
    ok = CliRunner().invoke(app, ["verify", "a.ru"])
    assert ok.exit_code == 0 and "подтверждено" in ok.output


def test_own_site_checks_need_the_flag():
    from suveren.catalog import SelectionError
    from suveren.plan import make_plan

    with pytest.raises(SelectionError, match="--own-site"):
        make_plan(checks="SUV-OWN-001")
    assert "ownsite" in make_plan(checks="SUV-OWN-001", own_site=True).modules
    assert "ownsite" not in make_plan(checks="web").modules
    assert "ownsite" in make_plan(own_site=True).modules


# --- exposed files --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "body", "found"),
    [
        ("/.git/HEAD", "ref: refs/heads/main\n", True),
        ("/.git/HEAD", "a" * 40, True),
        ("/.git/HEAD", "<html><body>Not found</body></html>", False),
        ("/.git/config", "[core]\n\trepositoryformatversion = 0\n", True),
        ("/.env", "DB_PASSWORD=x\nAPP_KEY=base64:abc\n", True),
        ("/.env", "Страница не найдена", False),
    ],
)
def test_looks_like_the_real_file(path, body, found):
    assert looks_like(path, 200, body) is found
    assert looks_like(path, 404, body) is False


def test_exposed_files_check_statuses():
    def leak(request):
        if request.url.path == "/.env":
            return httpx.Response(200, text="SECRET_KEY=1\n")
        return httpx.Response(404)

    async def go(handler):
        async with client(handler) as c:
            return await exposed_files_check(c, "a.ru")

    check = run(go(leak))
    assert check.id == "SUV-OWN-001" and check.status is Status.FAIL
    assert check.evidence[0].value == "https://a.ru/.env"
    assert run(go(lambda r: httpx.Response(404))).status is Status.OK

    def down(request):
        raise httpx.ConnectError("no", request=request)

    assert run(go(down)).status is Status.UNKNOWN


# --- TLS in depth ---------------------------------------------------------------------


def test_deep_tls_check():
    assert deep_tls_check(DeepTls()).status is Status.UNKNOWN
    ok = deep_tls_check(DeepTls("EC 256", False, False, {"3DES": False, "RC4": None}))
    assert ok.id == "SUV-OWN-002" and ok.status is Status.OK
    assert "RC4 проверить не удалось" in ok.details and "OCSP stapling не проверяется" in ok.details
    weak = deep_tls_check(DeepTls("RSA 1024", True, True, {"3DES": False}))
    assert weak.status is Status.WARN and "SHA-1" in weak.details
    bad = deep_tls_check(DeepTls("RSA 2048", False, False, {"3DES": True}))
    assert bad.status is Status.FAIL and "RFC 7465" in bad.details


def test_describe_key():
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "a.ru")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    assert describe_key(cert) == ("EC 256", False)


# --- mail -----------------------------------------------------------------------------


def test_mail_transport_collects_mx_tlsa_and_starttls():
    resolver = Resolver(
        {
            ("a.ru", "MX"): ["10 mx1.a.ru.", "20 mx2.a.ru."],
            ("_25._tcp.mx1.a.ru", "TLSA"): ["3 1 1 " + base64.b16encode(b"x" * 32).decode()],
            ("_25._tcp.mx2.a.ru", "TLSA"): ["SERVFAIL"],
        }
    )

    async def probe(host, timeout):
        return {"mx1.a.ru": True, "mx2.a.ru": None}[host]

    items = run(collect_mail_transport(resolver, "a.ru", 5, probe))
    assert [(m.host, m.starttls, bool(m.tlsa)) for m in items] == [
        ("mx1.a.ru", True, True),
        ("mx2.a.ru", None, False),
    ]
    check = mail_transport_check(items)
    assert check.id == "SUV-OWN-003" and check.status is Status.OK
    assert "DANE (TLSA) опубликован для mx1.a.ru" in check.details
    assert "Порт 25 не ответил: mx2.a.ru" in check.details


def test_mail_transport_statuses():
    assert mail_transport_check([]).status is Status.UNKNOWN
    plain = mail_transport_check([MxTransport("mx.a.ru", False, [])])
    assert plain.status is Status.FAIL and "открытым текстом" in plain.details
    silent = mail_transport_check([MxTransport("mx.a.ru", None, [])])
    assert silent.status is Status.UNKNOWN
    assert run(collect_mail_transport(Resolver({("a.ru", "MX"): ["SERVFAIL"]}), "a.ru", 5)) == []
