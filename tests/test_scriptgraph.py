from suveren.checks import Status
from suveren.render import initiator_url
from suveren.scriptgraph import SITE, build, graph_check, svg

GTM = "https://www.googletagmanager.com/gtm.js?id=GTM-X"
INITIATORS = {
    "https://site.ru/app.js": "",
    "https://cdn.site.ru/vendor.js": "",
    GTM: "https://site.ru/app.js",  # the site's own script loads the tag manager
    "https://mc.yandex.ru/metrika/tag.js": "",
    "https://connect.facebook.net/en_US/fbevents.js": GTM,  # chosen by the tag manager
    "https://ads.example-net.com/x.js": "https://connect.facebook.net/en_US/fbevents.js",
}


def test_graph_nodes_edges_and_depth():
    g = build(INITIATORS, "site.ru")
    assert set(g.third_party) == {
        "googletagmanager.com",
        "yandex.ru",
        "facebook.net",
        "example-net.com",
    }
    assert ("googletagmanager.com", "facebook.net") in g.edges
    assert (SITE, "googletagmanager.com") in g.edges  # own script = the site
    assert g.depth["example-net.com"] == 3
    assert g.indirect == ["example-net.com", "facebook.net"]


def test_check_names_what_the_site_did_not_choose():
    check = graph_check(build(INITIATORS, "site.ru"))
    assert check.status is Status.WARN and check.id == "SUV-WEB-011"
    assert "4 сторонних компаний" in check.details and "2 из них" in check.details
    assert "3 звена" in check.details
    direct = {"https://mc.yandex.ru/metrika/tag.js": ""}
    assert graph_check(build(direct, "site.ru")).status is Status.OK
    assert graph_check(build({}, "site.ru")).status is Status.OK


def test_svg_is_self_contained_and_escaped():
    g = build({**INITIATORS, "https://x.io/<b>.js": GTM}, "site.ru")
    out = svg(g)
    assert out.startswith("<svg") and "<script" not in out
    assert "<b>" not in out
    assert svg(build({}, "site.ru")) == ""


def test_initiator_from_devtools_stack():
    parser = {"type": "parser", "url": "https://site.ru/"}
    assert initiator_url(parser) == ""
    nested = {
        "type": "script",
        "stack": {
            "callFrames": [{"url": ""}],
            "parent": {"callFrames": [{"url": "https://www.googletagmanager.com/gtm.js"}]},
        },
    }
    assert initiator_url(nested) == "https://www.googletagmanager.com/gtm.js"
