"""The Russian Ministry root: bundled, consistent, and trusted for fedsfm.ru only."""

import asyncio
import ssl

import httpx
from cryptography import x509

from suveren import net


def test_bundled_chain_is_the_root_and_its_sub_cas():
    certs = x509.load_pem_x509_certificates(net.RU_ROOT.read_bytes())
    root, *subs = certs
    assert root.subject == root.issuer
    assert "Russian Trusted Root CA" in root.subject.rfc4514_string()
    assert len(subs) == 2
    for sub in subs:
        sub.verify_directly_issued_by(root)
    ssl.create_default_context().load_verify_locations(cafile=str(net.RU_ROOT))


def test_only_the_listed_hosts_go_through_the_russian_root():
    seen: list[tuple[str, str]] = []

    def transport(name: str) -> httpx.MockTransport:
        def handler(request: httpx.Request) -> httpx.Response:
            seen.append((name, request.url.host))
            return httpx.Response(200)

        return httpx.MockTransport(handler)

    async def go() -> None:
        routed = net._ByHost(transport("usual"), transport("ru"))
        async with httpx.AsyncClient(transport=routed) as client:
            for url in (
                "https://www.fedsfm.ru/x",
                "https://fedsfm.ru/",
                "https://example.ru/",
                "https://fedsfm.ru.evil.test/",
            ):
                await client.get(url)

    asyncio.run(go())
    assert seen == [
        ("ru", "www.fedsfm.ru"),
        ("ru", "fedsfm.ru"),
        ("usual", "example.ru"),
        ("usual", "fedsfm.ru.evil.test"),
    ]


def test_no_verification_means_no_routing():
    assert isinstance(net.guarded_transport(verify=False), httpx.AsyncHTTPTransport)
    assert isinstance(net.guarded_transport(), net._ByHost)
