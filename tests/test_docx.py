"""The report as .docx: a valid package Word opens, with the checks in it."""

import zipfile
from xml.dom import minidom

from suveren.checks import Check, Status
from suveren.docx import document_xml, write_docx
from suveren.models import Report


def report():
    return Report(
        "shop.ru",
        checks=[
            Check("Безопасность сайта", "Принудительный HTTPS (HSTS)", Status.WARN,
                  "Нет HSTS <&> \x1b[31m", "Добавьте заголовок."),
            Check("Персональные данные (152-ФЗ)", "Политика обработки персональных данных",
                  Status.FAIL, "Политики нет.", "Опубликуйте политику."),
        ],
    )  # fmt: skip


def test_docx_is_a_valid_package(tmp_path):
    path = write_docx(report(), tmp_path / "r.docx")
    with zipfile.ZipFile(path) as z:
        assert set(z.namelist()) == {"[Content_Types].xml", "_rels/.rels", "word/document.xml"}
        xml = z.read("word/document.xml").decode("utf-8")
    minidom.parseString(xml)  # well-formed: Word refuses a broken document
    assert "Отчёт Suveren: shop.ru" in xml and "SUV-WEB-005" in xml
    assert "Нет HSTS &lt;&amp;&gt;" in xml and "\x1b" not in xml
    assert "проблема" in xml and "Что сделать первым" in xml and "Штрафы" in xml


def test_docx_of_an_empty_report():
    xml = document_xml(Report("a.ru"))
    minidom.parseString(xml)
    assert "Что сделать первым" not in xml
