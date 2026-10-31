"""What gets installed is pinned: locks with hashes, the base image by digest, narrow
rights in the release workflow."""

import re
from pathlib import Path

ROOT = Path(__file__).parent.parent


def _pins(path: Path) -> dict[str, set[str]]:
    """package -> versions in a lock (a package can have one per Python version)."""
    pins: dict[str, set[str]] = {}
    for line in path.read_text("utf-8").splitlines():
        m = re.match(r"([a-z0-9][a-z0-9._-]*)==([^ ;\\]+)", line)
        if m:
            pins.setdefault(m.group(1).lower(), set()).add(m.group(2))
    return pins


def _hashed(path: Path) -> bool:
    text = path.read_text("utf-8")
    entries = [ln for ln in text.splitlines() if re.match(r"[a-z0-9]", ln)]
    return bool(entries) and text.count("--hash=sha256:") >= len(entries)


def test_browser_lock_is_the_base_lock_plus_playwright():
    base = _pins(ROOT / "packaging/requirements.txt")
    release = _pins(ROOT / "packaging/requirements-release.txt")
    browser = _pins(ROOT / "packaging/requirements-browser.txt")
    assert _hashed(ROOT / "packaging/requirements-browser.txt")
    for name, versions in base.items():
        assert browser.get(name) == versions, name
    for name in ("playwright", "greenlet", "pyee"):
        assert browser[name] == release[name], name


def test_suveren_bat_installs_with_hashes():
    bat = (ROOT / "Suveren.bat").read_text("utf-8")
    assert "--require-hashes -r packaging\\requirements-browser.txt" in bat
    assert '-e ".[browser]"' not in bat
    assert "--no-deps -e ." in bat


def test_docker_base_image_is_pinned_by_digest():
    froms = [ln for ln in (ROOT / "Dockerfile").read_text("utf-8").splitlines()
             if ln.startswith("FROM ")]  # fmt: skip
    assert froms and all(re.search(r"@sha256:[0-9a-f]{64}$", ln) for ln in froms)


def test_release_writes_to_the_repository_only_in_the_publishing_job():
    text = (ROOT / ".github/workflows/release.yml").read_text("utf-8")
    jobs = re.split(r"\n  (?=[a-z-]+:\n)", text.split("\njobs:\n", 1)[1])
    writers = [j.split(":", 1)[0] for j in jobs if "contents: write" in j]
    assert writers == ["github-release"]
    assert "permissions: {}" in text.split("\njobs:\n", 1)[0]
    publishing = next(j for j in jobs if j.startswith("github-release"))
    assert "pip install" not in publishing and "checkout" not in publishing


def test_dependabot_watches_pip_and_docker():
    text = (ROOT / ".github/dependabot.yml").read_text("utf-8")
    for ecosystem in ("github-actions", "pip", "docker"):
        assert f"package-ecosystem: {ecosystem}" in text


def test_ci_audits_the_locks():
    ci = (ROOT / ".github/workflows/ci.yml").read_text("utf-8")
    for lock in ("requirements.txt", "requirements-browser.txt", "requirements-release.txt"):
        assert f"--require-hashes -r packaging/{lock}" in ci


def test_suveren_bat_explains_a_failed_install():
    bat = (ROOT / "Suveren.bat").read_text("utf-8")
    assert bat.count("--log .venv\\install.log") == 2
    assert "Последние строки журнала установки" in bat and "DO NOT MATCH THE HASHES" in bat
