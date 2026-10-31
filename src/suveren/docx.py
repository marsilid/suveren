"""The report as a Word document (.docx), with no extra dependency.

A .docx is a zip of a few XML files (ECMA-376). Suveren writes the minimal set by hand:
the title, the grades, what to do first, the fines and every check with its status and
details, so the report can be edited and sent as a document. The HTML report stays the
full one (evidence, services, the migration plan).
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

from suveren.advice import overall_grade, overall_score, priorities
from suveren.fines import rub
from suveren.models import Report
from suveren.utils import clean_text

_PKG = "http://schemas.openxmlformats.org/package/2006"
_OFFICE = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_MAIN = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
_CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    f'<Types xmlns="{_PKG}/content-types">'
    '<Default Extension="rels" '
    'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    f'<Override PartName="/word/document.xml" ContentType="{_MAIN}"/>'
    "</Types>"
)
_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    f'<Relationships xmlns="{_PKG}/relationships">'
    f'<Relationship Id="rId1" Type="{_OFFICE}/officeDocument" Target="word/document.xml"/>'
    "</Relationships>"
)
_NS = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
STATUS_RU = {"ok": "в порядке", "warn": "внимание", "fail": "проблема", "unknown": "не ясно"}
STATUS_COLOR = {"ok": "4F8A3C", "warn": "A8740F", "fail": "C93C35", "unknown": "6B7280"}


def _run(text: str, *, bold: bool = False, size: int | None = None, color: str = "") -> str:
    props = ""
    if bold or size or color:
        props = "<w:rPr>"
        props += "<w:b/>" if bold else ""
        props += f'<w:color w:val="{color}"/>' if color else ""
        props += f'<w:sz w:val="{size}"/>' if size else ""
        props += "</w:rPr>"
    # Word keeps no raw control characters; the text is already cleaned of them.
    return f'<w:r>{props}<w:t xml:space="preserve">{escape(clean_text(text))}</w:t></w:r>'


def _p(*runs: str) -> str:
    return "<w:p>" + "".join(runs) + "</w:p>"


def _cell(content: str, width: int) -> str:
    return f'<w:tc><w:tcPr><w:tcW w:w="{width}" w:type="dxa"/></w:tcPr>{content}</w:tc>'


def document_xml(report: Report) -> str:
    body = [
        _p(_run(f"Отчёт Suveren: {report.target}", bold=True, size=36)),
        _p(_run(f"Проверено {report.started_at:%d.%m.%Y}.")),
        _p(
            _run("Общая оценка: ", bold=True),
            _run(f"{overall_grade(report)} ({overall_score(report)}/100). "),
            _run("Независимость: ", bold=True),
            _run(f"{report.grade} ({report.score}/100)."),
        ),
    ]
    actions = priorities(report)[:5]
    if actions:
        body.append(_p(_run("Что сделать первым", bold=True, size=28)))
        body += [_p(_run(f"{i}. {a.action}", bold=True), _run(f" {a.reason}"))
                 for i, a in enumerate(actions, 1)]  # fmt: skip
    fines = report.fines
    if fines:
        body.append(_p(_run("Штрафы", bold=True, size=28)))
        total = f"до {rub(fines.total('legal'))}" if fines.counted else "безусловных нет"
        body.append(_p(_run(f"Для юрлица: {total}; условных: {len(fines.listed)}.")))
    for group, checks in report.check_groups:
        body.append(_p(_run(group, bold=True, size=28)))
        rows = []
        for c in checks:
            status = c.status.value
            rows.append(
                "<w:tr>"
                + _cell(_p(_run(STATUS_RU[status], bold=True, color=STATUS_COLOR[status])), 1500)
                + _cell(_p(_run(c.title, bold=True)) + _p(_run(c.details)), 6500)
                + _cell(_p(_run(c.id)), 1500)
                + "</w:tr>"
            )
        body.append(
            '<w:tbl><w:tblPr><w:tblW w:w="9500" w:type="dxa"/><w:tblBorders>'
            '<w:insideH w:val="single" w:sz="4" w:color="E1E4E8"/></w:tblBorders></w:tblPr>'
            + "".join(rows)
            + "</w:tbl>"
        )
    body.append(_p(_run("Отчёт помогает расставить приоритеты и не является юридическим "
                        "заключением. Подробности и доказательства — в HTML-отчёте.")))  # fmt: skip
    return (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document {_NS}><w:body>'
        + "".join(body)
        + "</w:body></w:document>"
    )


def write_docx(report: Report, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _CONTENT_TYPES)
        z.writestr("_rels/.rels", _RELS)
        z.writestr("word/document.xml", document_xml(report))
    return path
