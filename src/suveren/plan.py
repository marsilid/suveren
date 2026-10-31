"""What one scan runs: the profile, ``--checks`` and the ``--no-*`` switches turned
into modules, browser mode and pages. ``scan``, ``batch`` and the menu share it, so
they behave the same."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from suveren.catalog import SelectionError, modules_for, select
from suveren.crawl import DEFAULT_PAGES

SCAN_MODULES = (
    "compliance", "blocklist", "mail", "security", "subdomains", "cutoff", "formleaks", "ownsite",
)  # fmt: skip
# The cutoff experiment opens the site three more times in a browser: on request only.
# The form experiment types into the site's forms: only with its own flag, never by a
# profile, so nobody runs it on a site without meaning to.
DEFAULT_MODULES = frozenset(SCAN_MODULES) - {"cutoff", "formleaks", "ownsite"}
OWN_SITE_ONLY = (
    "вводит тестовые данные в формы и прощупывает сайт, поэтому работает только для своего "
    "сайта: добавьте --own-site и подтвердите владение (suveren verify сайт)"
)
DEEP_PAGES = 12


class Profile(str, Enum):
    quick = "quick"  # foreign services only: seconds, no extra requests
    standard = "standard"  # everything passive over HTTP (the default)
    deep = "deep"  # plus a real browser, more inner pages and the cutoff experiment


PROFILE_HELP = (
    "quick — только иностранные сервисы; standard — все проверки (по умолчанию); "
    f"deep — все проверки в браузере, до {DEEP_PAGES} внутренних страниц и эксперимент "
    "с отключением иностранных сервисов (--cutoff)."
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
    cutoff: bool = False,
    form_leaks: bool = False,
    own_site: bool = False,
) -> ScanPlan:
    """``checks`` narrows the modules to those the chosen checks need; ``skip`` comes
    from the --no-* switches and always wins. Raises ``SelectionError`` on an unknown
    word in ``checks``."""
    modules = set() if profile is Profile.quick else set(DEFAULT_MODULES)
    if cutoff or profile is Profile.deep:
        modules.add("cutoff")
    if form_leaks and not own_site:
        raise SelectionError(f"--form-leaks {OWN_SITE_ONLY}")
    if form_leaks:
        modules.add("formleaks")
    if own_site:
        modules.add("ownsite")
    only: frozenset[str] | None = None
    if checks:
        only = frozenset(select(checks))
        # Explicitly chosen checks run even in the quick profile.
        modules = modules_for(set(only)) & set(SCAN_MODULES)
        if cutoff:
            modules.add("cutoff")
        if own_site:
            modules.add("ownsite")
        elif modules & {"ownsite"} and modules <= {"ownsite", "formleaks"}:
            raise SelectionError(f"--checks: проверки «свой сайт» {OWN_SITE_ONLY}")
        else:
            modules.discard("ownsite")
        if form_leaks:
            modules.add("formleaks")
        elif modules == {"formleaks"}:
            raise SelectionError(
                "--checks: эксперимент с формами вводит тестовые данные в формы сайта и "
                "запускается только с флагом --form-leaks"
            )
        else:  # "--checks pd" and the like: the experiment stays off without its flag
            modules.discard("formleaks")
    modules -= set(skip)
    if profile is Profile.deep:
        browser, pages = True, max(pages, DEEP_PAGES)
    return ScanPlan(frozenset(modules), browser, pages, only)
