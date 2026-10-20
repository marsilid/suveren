import asyncio

import pytest
from test_view import sample_report

from suveren.brand import brand_from
from suveren.errors import ModuleError, SuverenError
from suveren.report import render_html, write_html

PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010806000000"
    "1f15c4890000000d49444154789c6360000002000154a24f5d0000000049454e44ae426082"
)


def test_brand_in_header_and_footer_with_suveren_credit(tmp_path):
    logo = tmp_path / "logo.png"
    logo.write_bytes(PNG)
    brand = brand_from("Студия Север", logo, "sever.ru")
    html = render_html(sample_report(), brand)
    assert '<span class="brand"><img class="brand-logo" src="data:image/png;base64,' in html
    assert "Студия Север" in html and 'href="https://sever.ru"' in html
    assert "Сделано с помощью Suveren" in html  # MIT: the credit stays
    plain = render_html(sample_report())
    assert '<span class="brand">Suveren</span>' in plain and "Студия" not in plain


def test_brand_from_environment_and_errors(tmp_path, monkeypatch):
    assert brand_from() is None
    monkeypatch.setenv("SUVEREN_BRAND_NAME", "Студия")
    assert brand_from().name == "Студия"
    monkeypatch.delenv("SUVEREN_BRAND_NAME")
    with pytest.raises(SuverenError):
        brand_from(url="sever.ru")  # a link without a name
    bad = tmp_path / "logo.exe"
    bad.write_bytes(b"MZ")
    with pytest.raises(SuverenError):
        brand_from("Студия", bad)
    with pytest.raises(SuverenError):
        brand_from("Студия", tmp_path / "missing.png")


def test_pdf_prints_when_a_browser_is_available(tmp_path):
    pytest.importorskip("playwright")
    from suveren.render import print_pdf

    html = write_html(sample_report(), tmp_path / "r.html")
    try:
        pdf = asyncio.run(print_pdf(html, tmp_path / "r.pdf"))
    except ModuleError as exc:
        pytest.skip(f"no browser: {exc}")
    data = pdf.read_bytes()
    assert data.startswith(b"%PDF") and len(data) > 5000


def test_brand_url_case_and_blank_name():
    assert brand_from("Студия", url="HTTPS://studio.ru").url == "HTTPS://studio.ru"
    assert brand_from("   ") is None
