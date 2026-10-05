from datetime import date

from suveren.blocklist import domain_candidates, find_blocked_domains, find_blocked_ips
from suveren.registries import parse_egrul_rows, parse_rkn_operators


def test_parse_egrul_rows():
    payload = {
        "rows": [
            {
                "c": "ПАО СБЕРБАНК",
                "g": "ПРЕЗИДЕНТ, ПРЕДСЕДАТЕЛЬ ПРАВЛЕНИЯ: Греф Герман Оскарович",
                "i": "7707083893",
                "k": "ul",
                "n": 'ПУБЛИЧНОЕ АКЦИОНЕРНОЕ ОБЩЕСТВО "СБЕРБАНК РОССИИ"',
                "o": "1027700132195",
                "p": "773601001",
                "r": "16.08.2002",
                "rn": "Г.Москва",
            }
        ]
    }
    [rec] = parse_egrul_rows(payload)
    assert rec.inn == "7707083893"
    assert rec.registered == date(2002, 8, 16)
    assert rec.active
    assert rec.head_name == "Греф Герман Оскарович"
    assert not rec.individual


def test_parse_egrul_terminated():
    [rec] = parse_egrul_rows({"rows": [{"n": "ООО РОМАШКА", "e": "01.02.2020", "k": "ul"}]})
    assert not rec.active
    assert rec.terminated == date(2020, 2, 1)


RKN_ROW = """
<table><tr class='clmn1'>
 <td width='42' valign='top'><nobr>11-0187199</nobr><br></td>
 <td>
    <a href="?id=11-0187199">Публичное акционерное общество "Сбербанк России"</a><br/>
    ИНН: 7707083893<br/>юридическое лицо
 </td>
 <td valign='top'>Приказ&nbsp;№&nbsp;229 от&nbsp;06.04.2011</td>
 <td valign='top'>24.03.2011</td>
 <td valign='top'>26.07.1991</td>
</tr></table>
"""


def test_parse_rkn_operators():
    [op] = parse_rkn_operators(RKN_ROW)
    assert op.reg_number == "11-0187199"
    assert op.inn == "7707083893"
    assert op.name.startswith("Публичное акционерное общество")
    assert op.basis == "Приказ № 229 от 06.04.2011"
    assert op.registered == date(2011, 3, 24)
    assert op.url.endswith("?id=11-0187199")


def test_domain_candidates():
    assert domain_candidates("a.b.example.ru") == ["a.b.example.ru", "b.example.ru", "example.ru"]


def test_find_blocked_domains_normalizes_entries():
    lines = ['"blocked.ru\n', "*.other.org\n", "fine.ru\n"]
    assert find_blocked_domains(lines, domain_candidates("www.blocked.ru")) == {"blocked.ru"}
    assert find_blocked_domains(lines, ["other.org"]) == {"other.org"}
    assert find_blocked_domains(lines, ["example.ru"]) == set()


def test_find_blocked_ips():
    lines = ["1.2.3.4\n", "10.0.0.0/8\n", "# comment\n", "garbage\n"]
    assert find_blocked_ips(lines, ["1.2.3.4", "10.1.2.3", "8.8.8.8"]) == {
        "1.2.3.4": "1.2.3.4",
        "10.1.2.3": "10.0.0.0/8",
    }
