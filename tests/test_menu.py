from pathlib import Path

from rich.console import Console

from suveren.menu import run_menu


class FakeApp:
    def __init__(self):
        self.calls = []

    def __call__(self, args, standalone_mode=True):
        self.calls.append(args)


def run(answers):
    console = Console(record=True, width=100)
    feed = iter(answers)
    console.input = lambda prompt="": next(feed, "0")  # type: ignore[method-assign]
    console.clear = lambda *a, **k: None  # type: ignore[method-assign]
    app = FakeApp()
    run_menu(app, console)
    return app.calls


def test_quick_site_check():
    # Enter is the ordinary check (~20 s, no browser).
    calls = run(["1", "example.ru", "", "", "", "0"])
    assert calls == [["scan", "example.ru", "--profile", "standard"]]


def test_flags_after_the_address_are_used_and_not_asked_again():
    calls = run(["1", "https://site.ru/#top --profile deep --pages 30 --pdf r.pdf", "", "0"])
    assert calls == [["scan", "https://site.ru/#top", "--profile", "deep", "--pages", "30",
                      "--pdf", "r.pdf"]]  # fmt: skip
    # Flags that leave the questions open: both are still asked.
    calls = run(["1", "site.ru --timeout 20", "2", "", "", "0"])
    assert calls == [["scan", "site.ru", "--profile", "deep", "--timeout", "20"]]


def test_deep_check_with_pdf():
    calls = run(["1", "https://example.ru/", "2", "да", "", "0"])
    pdf = str(Path("reports") / "https___example.ru_.pdf")
    assert calls == [["scan", "https://example.ru/", "--profile", "deep", "--pdf", pdf]]


def test_a_bad_flag_is_said_and_the_menu_stays():
    import typer

    class Strict(FakeApp):
        def __call__(self, args, standalone_mode=True):
            super().__call__(args, standalone_mode)
            raise typer.BadParameter("Option '--json' requires an argument.")

    console = Console(record=True, width=100)
    feed = iter(["1", "habr.com --json", "", "", "", "0"])
    console.input = lambda prompt="": next(feed, "0")  # type: ignore[method-assign]
    console.clear = lambda *a, **k: None  # type: ignore[method-assign]
    run_menu(Strict(), console)
    assert "Параметру --json нужно значение" in console.export_text()


def test_company_with_pdf():
    calls = run(["3", "7707083893", "д", "", "0"])
    pdf = str(Path("reports") / "7707083893.pdf")
    assert calls == [["company", "7707083893", "--browser", "--pdf", pdf]]
    assert run(["3", "7707083893", "", "", "0"]) == [["company", "7707083893", "--browser"]]


def test_watch_from_the_menu():
    assert run(["9", "sites.txt", "", "0"]) == [["watch", "sites.txt", "--once"]]
    assert run(["9", "", "", "0"]) == []
