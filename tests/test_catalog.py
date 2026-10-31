import ast
import re
from pathlib import Path

import pytest

from suveren import catalog, checks, company, mailsec, subdomains, websec
from suveren.catalog import BY_ID, CATALOG, MODULES, SelectionError, modules_for, select, spec_for

SRC = Path(checks.__file__).parent


def test_ids_are_unique_and_well_formed():
    ids = [s.id for s in CATALOG]
    assert len(ids) == len(set(ids))
    for spec in CATALOG:
        assert re.fullmatch(r"SUV-[A-Z]+-\d{3}", spec.id), spec.id
        assert spec.module in MODULES
        assert spec.tags and spec.summary.endswith(".")
    assert len({(s.group, s.title) for s in CATALOG}) == len(CATALOG)


def test_sections_match_the_modules():
    assert catalog.PD == checks.GROUP_152
    assert catalog.LAWS == checks.GROUP_LAWS
    assert catalog.BLOCK == checks.GROUP_BLOCK
    assert catalog.MAIL == mailsec.GROUP_MAIL
    assert catalog.WEB == websec.GROUP_WEB
    assert catalog.SUB == subdomains.GROUP_SUB
    assert catalog.COMPANY == company.GROUP


def _literal_titles():
    """(file, title) of every Check(...) built with a literal title or a title variable
    assigned a literal in the same file: the paths tests may not reach."""
    for path in sorted(SRC.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = {
            t.id: n.value.value
            for n in ast.walk(tree)
            if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant)
            for t in n.targets
            if isinstance(t, ast.Name) and isinstance(n.value.value, str)
        }
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and getattr(node.func, "id", None) == "Check"):
                continue
            if len(node.args) < 2:
                continue
            group, title = node.args[0], node.args[1]
            g = group.value if isinstance(group, ast.Constant) else names.get(group.id)
            if g is None and isinstance(group, ast.Name):
                g = getattr(checks, group.id, None) or {
                    "GROUP_MAIL": mailsec.GROUP_MAIL,
                    "GROUP_WEB": websec.GROUP_WEB,
                    "GROUP_SUB": subdomains.GROUP_SUB,
                    "GROUP": company.GROUP,
                }.get(group.id)
            if isinstance(title, ast.Constant):
                yield path.name, g, title.value
            elif isinstance(title, ast.Name) and title.id in names:
                yield path.name, g, names[title.id]


def test_every_check_in_the_code_is_in_the_catalog():
    found = list(_literal_titles())
    assert len(found) > 20
    missing = [(f, g, t) for f, g, t in found if spec_for(g, t) is None]
    assert missing == []


def test_fine_rules_refer_to_real_checks():
    from suveren.fines import RULES

    assert {i for i, _ in RULES} <= set(BY_ID)


def test_pattern_titles():
    assert spec_for(catalog.MAIL, "Можно ли подделать письмо от имени @habr.com").id == (
        "SUV-MAIL-001"
    )
    assert spec_for(catalog.WEB, "Можно ли подделать письмо от имени @habr.com") is None
    # The same title in two sections is two checks.
    assert spec_for(catalog.PD, "Реестр операторов персональных данных").id == "SUV-PD-009"
    assert spec_for(catalog.COMPANY, "Реестр операторов персональных данных").id == "SUV-CO-006"


def test_check_gets_its_id():
    check = checks.Check(catalog.WEB, "Флаги cookies", checks.Status.WARN)
    assert check.id == "SUV-WEB-007"
    assert check.to_dict()["id"] == "SUV-WEB-007"


def test_select_by_id_prefix_tag_and_module():
    assert select("SUV-MAIL-003") == {"SUV-MAIL-003"}
    assert select("suv-mail") == {s.id for s in CATALOG if s.id.startswith("SUV-MAIL-")}
    assert select("headers") == {"SUV-WEB-004", "SUV-WEB-005", "SUV-WEB-006"}
    assert select("subdomains") == {
        "SUV-SUB-000",
        "SUV-SUB-001",
        "SUV-SUB-002",
        "SUV-SUB-003",
        "SUV-ATK-003",
    }
    assert select("dkim, SUV-LAW-001") == {"SUV-MAIL-004", "SUV-MAIL-006", "SUV-LAW-001"}
    assert modules_for(select("headers,dkim")) == {"security", "mail"}
    # "SUV-MAIL-00" is not a prefix of whole parts: no accidental matches.
    with pytest.raises(SelectionError):
        select("SUV-MAIL-00")
    with pytest.raises(SelectionError):
        select("nmap")
    assert all(i in BY_ID for i in select("law"))


def test_docs_checks_md_is_up_to_date():
    from suveren.catalog import markdown

    path = SRC.parent.parent / "docs" / "checks.md"
    on_disk = path.read_text(encoding="utf-8").replace("\r\n", "\n").strip()
    assert on_disk == markdown().strip(), "run: suveren checks --markdown > docs/checks.md"


def test_every_check_has_both_labels():
    from suveren.catalog import LABELS, RUNNER_RISKS, SITE_ACTIONS

    assert set(LABELS) <= set(BY_ID)
    for s in catalog.CATALOG:
        assert s.site in SITE_ACTIONS and s.runner in RUNNER_RISKS, s.id
        # The site's JavaScript runs exactly in the checks that need a browser.
        assert (s.runner == "js") is ("browser" in s.tags), s.id
        # A check that does not touch the site cannot show it your IP, and the reverse.
        assert (s.site == "none") is (s.runner == "none"), s.id


def test_labels_follow_what_the_modules_do():
    # Mail and company checks read DNS and registers; TLS deliberately tries TLS 1.0/1.1;
    # form leaks types into forms. Checked against the code of each module.
    assert {BY_ID[i].site for i in ("SUV-MAIL-001", "SUV-MAIL-003", "SUV-CO-003")} == {"none"}
    assert BY_ID["SUV-MAIL-005"].site == "look"  # it opens the MTA-STS policy file
    assert BY_ID["SUV-WEB-008"].site == "probe"
    assert BY_ID["SUV-SUB-001"].site == "none" and BY_ID["SUV-SUB-002"].site == "probe"
    assert (BY_ID["SUV-PD-012"].site, BY_ID["SUV-PD-012"].runner) == ("input", "js")


def test_checks_command_shows_the_labels():
    from typer.testing import CliRunner

    from suveren.cli import app

    out = CliRunner().invoke(app, ["checks"]).output
    assert "С сайтом" in out and "прощупывает" in out and "JavaScript сайта" in out
    one = CliRunner().invoke(app, ["checks", "SUV-PD-012"]).output
    assert "вводит данные" in one and "выполняется JavaScript сайта" in one
