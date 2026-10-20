"""Services whose abandoned custom domains can be claimed by someone else.

Source: "Can I take over XYZ?" by EdOverflow and contributors,
https://github.com/EdOverflow/can-i-take-over-xyz (fingerprints.json, CC BY 4.0),
checked 2026-10-17. Only entries marked "Vulnerable" or "Edge case" are used. Where the
source gives no CNAME, the service's standard custom-domain target is filled in.
The entries live in data/takeover.json: ``added`` marks entries that are not in the
source and were added by Suveren; ``seen`` lists the placeholder texts these services
showed on 2026-10-17, kept next to the source's older wording.

``fingerprint`` is a regular expression searched in the page the subdomain serves,
``HTTP_STATUS=n`` means the status code, and ``nxdomain`` means the CNAME target
itself no longer exists.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib.resources import files

SOURCE_URL = "https://github.com/EdOverflow/can-i-take-over-xyz"


@dataclass(frozen=True, slots=True)
class Signature:
    service: str
    cnames: tuple[str, ...]  # suffixes of the CNAME target
    fingerprints: tuple[str, ...] = ()
    nxdomain: bool = False
    vulnerable: bool = True  # False: "Edge case" in the source, takeover is not always possible
    added: bool = False


def _load() -> tuple[Signature, ...]:
    raw = json.loads(files("suveren").joinpath("data/takeover.json").read_text("utf-8"))
    return tuple(
        Signature(
            d["service"],
            tuple(d["cnames"]),
            tuple(d.get("fingerprints", ())),
            nxdomain=d.get("nxdomain", False),
            vulnerable=d.get("vulnerable", True),
            added=d.get("added", False),
        )
        for d in raw["signatures"]
    )


SIGNATURES: tuple[Signature, ...] = _load()


def find_signature(targets: list[str]) -> Signature | None:
    """The service any of the CNAME targets points to, if it is a known one."""
    for target in targets:
        host = target.lower().rstrip(".")
        for sig in SIGNATURES:
            if any(host == s or host.endswith("." + s) for s in sig.cnames):
                return sig
    return None
