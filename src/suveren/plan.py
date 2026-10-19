"""What one scan runs: the profile, ``--checks`` and the ``--no-*`` switches turned
into modules, browser mode and pages. ``scan``, ``batch`` and the menu share it, so
they behave the same."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from suveren.catalog import modules_for, select
from suveren.crawl import DEFAULT_PAGES

SCAN_MODULES = ("compliance", "blocklist", "mail", "security", "subdomains")
DEEP_PAGES = 12


class Profile(str, Enum):
    quick = "quick"  # foreign services only: seconds, no extra requests
    standard = "standard"  # everything passive over HTTP (the default)
    deep = "deep"  # plus a real browser and more inner pages


PROFILE_HELP = (
    "quick — только иностранные сервисы; standard — все проверки (по умолчанию); "
    f"deep — все проверки в браузере и до {DEEP_PAGES} внутренних страниц."
)


@dataclass(frozen=True, slots=True)
class ScanPlan:
    modules: frozenset[str]
    browser: bool
    pages: int
    only: frozenset[str] | None = None  # check IDs to report; None = all

    def kwargs(self) -> dict[str, object]:
        """Arguments for ``run_scan``."""
        return {
            **{m: m in self.modules for m in SCAN_MODULES},
            "browser": self.browser,
            "pages": self.pages,
            "only": self.only,
        }


def make_plan(
    profile: Profile = Profile.standard,
    checks: str | None = None,
    *,
    browser: bool = False,
    pages: int = DEFAULT_PAGES,
    skip: frozenset[str] | set[str] = frozenset(),
) -> ScanPlan:
    """``checks`` narrows the modules to those the chosen checks need; ``skip`` comes
    from the --no-* switches and always wins. Raises ``SelectionError`` on an unknown
    word in ``checks``."""
    modules = set() if profile is Profile.quick else set(SCAN_MODULES)
    only: frozenset[str] | None = None
    if checks:
        only = frozenset(select(checks))
        # Explicitly chosen checks run even in the quick profile.
        modules = modules_for(set(only)) & set(SCAN_MODULES)
    modules -= set(skip)
    if profile is Profile.deep:
        browser, pages = True, max(pages, DEEP_PAGES)
    return ScanPlan(frozenset(modules), browser, pages, only)
