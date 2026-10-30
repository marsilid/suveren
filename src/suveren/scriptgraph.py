"""Who loads whose code: the chain of third-party scripts behind a page.

In --browser mode the browser reports which script started each script request
(render.initiator_url). That gives a graph: the site loads a tag manager, the tag
manager loads an ad network, the ad network loads three more. The owner of the site
chose only the first link; the rest runs on its pages all the same. Nodes are
registrable domains (one per company, roughly); the site's own domain is one node.
"""

from __future__ import annotations

import html
from collections import deque
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from suveren.checks import Check, Status
from suveren.cutoff import known_service
from suveren.utils import registrable_domain

TITLE = "Цепочки сторонних скриптов"
GROUP_WEB = "Безопасность сайта"
SITE = "сайт"
SHOWN = 6


@dataclass(slots=True)
class Graph:
    nodes: dict[str, str] = field(default_factory=dict)  # domain -> owner label
    edges: set[tuple[str, str]] = field(default_factory=set)  # (loader, loaded)
    depth: dict[str, int] = field(default_factory=dict)

    @property
    def third_party(self) -> list[str]:
        return sorted(n for n in self.nodes if n != SITE)

    @property
    def indirect(self) -> list[str]:
        """Third parties no page of the site loads itself: someone else's script did."""
        direct = {b for a, b in self.edges if a == SITE}
        return sorted(n for n in self.third_party if n not in direct)

    def loaders(self, node: str) -> list[str]:
        return sorted(a for a, b in self.edges if b == node)

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [{"domain": n, "owner": o, "depth": self.depth.get(n)} for n, o in
                      sorted(self.nodes.items())],
            "edges": sorted([a, b] for a, b in self.edges),
        }  # fmt: skip


def _node(url: str, own: str) -> str:
    host = (urlsplit(url).hostname or "").lower()
    if not host:
        return SITE
    domain = registrable_domain(host)
    return SITE if domain == own else domain


def build(initiators: dict[str, str], site: str) -> Graph:
    """``initiators``: script URL -> URL of the script that loaded it ("" = the page)."""
    own = registrable_domain(site)
    g = Graph(nodes={SITE: site})
    for script, loader in initiators.items():
        if urlsplit(script).scheme not in ("http", "https"):
            continue
        b = _node(script, own)
        a = _node(loader, own) if loader else SITE
        if b == SITE:
            continue  # the site's own code, whoever loaded it
        if b not in g.nodes:
            svc = known_service(script)
            g.nodes[b] = svc.label() if svc else b
        if a not in g.nodes:
            svc = known_service(loader) if loader else None
            g.nodes[a] = svc.label() if svc else a
        if a != b:
            g.edges.add((a, b))
    # Depth: how many links from the site; a node reachable only through cycles keeps none.
    queue = deque([SITE])
    g.depth[SITE] = 0
    while queue:
        a = queue.popleft()
        for x, b in sorted(g.edges):
            if x == a and b not in g.depth:
                g.depth[b] = g.depth[a] + 1
                queue.append(b)
    return g


def graph_check(g: Graph) -> Check:
    total = len(g.third_party)
    if not total:
        return Check(GROUP_WEB, TITLE, Status.OK, "Сторонних скриптов на главной нет.")
    indirect = g.indirect
    if not indirect:
        return Check(
            GROUP_WEB,
            TITLE,
            Status.OK,
            f"Код {total} сторонних компаний подключён самим сайтом: чужие скрипты ничего не "
            "подгружают дальше.",
        )
    longest = max((d for d in g.depth.values() if d is not None), default=1)

    def via(n: str) -> str:
        return ", ".join(g.nodes[x] if x != SITE else "сайт" for x in g.loaders(n))

    shown = "; ".join(f"{g.nodes[n]} — через {via(n)}" for n in indirect[:SHOWN])
    more = f" и ещё {len(indirect) - SHOWN}" if len(indirect) > SHOWN else ""
    return Check(
        GROUP_WEB,
        TITLE,
        Status.WARN,
        f"Сайт выполняет код {total} сторонних компаний; {len(indirect)} из них подключил не "
        f"сайт, а чужие скрипты: {shown}{more}. Самая длинная цепочка — {longest} звена. "
        "Этот код меняется без вашего ведома, и он видит всё, что вводят посетители.",
        "Уберите из тег-менеджера и виджетов то, чем не пользуетесь, и ограничьте источники "
        "скриптов в CSP: тогда новый код без вашего ведома не запустится.",
    )


def svg(g: Graph) -> str:
    """The graph as inline SVG: columns by distance from the site, no JavaScript."""
    columns: dict[int, list[str]] = {}
    for n, d in sorted(g.depth.items(), key=lambda x: (x[1], x[0])):
        columns.setdefault(d, []).append(n)
    if len(columns) < 2:
        return ""
    w, h, gap_x, gap_y = 210, 28, 60, 12
    pos: dict[str, tuple[int, int]] = {}
    for d, nodes in columns.items():
        for i, n in enumerate(nodes):
            pos[n] = (10 + d * (w + gap_x), 10 + i * (h + gap_y))
    width = 20 + len(columns) * (w + gap_x) - gap_x
    height = 20 + max(len(v) for v in columns.values()) * (h + gap_y) - gap_y
    parts = [
        f'<svg class="graph" viewBox="0 0 {width} {height}" width="100%" '
        f'role="img" aria-label="Кто подключает сторонние скрипты">'
    ]
    for a, b in sorted(g.edges):
        if a in pos and b in pos:
            x1, y1 = pos[a][0] + w, pos[a][1] + h // 2
            x2, y2 = pos[b][0], pos[b][1] + h // 2
            mid = (x1 + x2) // 2
            parts.append(f'<path d="M{x1},{y1} C{mid},{y1} {mid},{y2} {x2},{y2}" class="edge"/>')
    indirect = set(g.indirect)
    for n, (x, y) in pos.items():
        # Cut, then escape: cutting "&amp;" in half would leave a broken entity.
        label = html.escape((g.nodes[n] if n != SITE else g.nodes[SITE])[:30])
        cls = "site" if n == SITE else "indirect" if n in indirect else "direct"
        parts.append(
            f'<g class="node {cls}"><rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6"/>'
            f'<text x="{x + 8}" y="{y + 18}">{label}</text></g>'
        )
    parts.append("</svg>")
    return "".join(parts)
