"""Form data that leaves before the form is sent: an experiment in a real browser.

Session recorders, keyloggers in analytics, "lost lead" widgets and ad pixels with
automatic matching read what a visitor types and send it before the visitor presses
"Отправить", let alone ticks the consent box. The method follows Senol et al., "Leaky
Forms" (USENIX Security 2022): type unique test values into the name, phone, e-mail
and password fields, never send the form, and look for the values in every request the
page makes, in the clear, URL-encoded, in base64, compressed or as MD5/SHA-1/SHA-256
hashes (ad pixels hash e-mails and phones).

The values can't reach anyone: the e-mail is at example.com (RFC 2606), the phone's
area code 100 does not exist in the Russian numbering plan, and a phone that an input
mask turned into another number is erased (render.fill_forms). The form is never
submitted: submit events are cancelled before the site's handlers run.

Why it matters (152-ФЗ, checked against the text on consultant.ru, 2026-10-24):
ст. 7 — whoever has access to personal data must not disclose it to third parties
without the person's consent; ст. 6 ч. 3 — processing may be entrusted to another
person only with the person's consent. Before submission there is no consent at all.
A foreign recipient adds cross-border transfer (ст. 12).
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import gzip
import hashlib
import re
import secrets
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote_plus, urlsplit

from suveren.checks import GROUP_152, Check, Status
from suveren.cutoff import HostInfo, classify
from suveren.errors import ModuleError
from suveren.render import FORM_FLUSH_MS, FORM_WATCH_MS, FormProbe, Sent
from suveren.utils import registrable_domain

TITLE = "Данные из форм до отправки"
# Said before the experiment runs: it touches the site's forms.
NOTE = (
    "Эксперимент с формами: в поля имени, телефона, почты и пароля вводятся тестовые "
    "данные (адрес @example.com, номер с несуществующим кодом 100), формы не "
    "отправляются. Виджеты «брошенных заявок» могут показать владельцу тестовую заявку."
)
# The mask of many Russian forms takes only numbers starting with 9: then the made-up
# number can't be typed, and only the owner's own number (--form-phone) tests the phone.
MASK_NOTE = (
    " Телефон проверить не удалось: маска поля не принимает тестовый номер, а настоящий "
    "номер вводить нельзя — он может оказаться чужим. Для своего сайта укажите свой номер: "
    "--form-phone."
)
LAW = "152-ФЗ, ст. 7, ст. 6 ч. 3"
MAX_PAGES = 3
SHOWN = 5

KIND_RU = {"name": "имя", "phone": "телефон", "email": "почта", "password": "пароль"}
KIND_ORDER = ("password", "phone", "email", "name")

PLAIN = "открытым текстом"
PACKED = "в сжатом виде"
BASE64 = "в base64"

_CONSONANTS = "бвгдзклмнпрстфх"
_VOWELS = "аеиоу"
_ALNUM = "abcdefghijkmnpqrstuvwxyz23456789"
_MAX_UNPACKED = 8 * 1024 * 1024
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_JSON_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")


@dataclass(frozen=True, slots=True)
class Canaries:
    """The test values typed into the fields. Each holds a random part that can't occur
    by chance in a request, so finding it proves the field was read."""

    email: str
    phone: str  # ten digits as typed; the mask adds +7 and the brackets
    password: str
    name: str

    own_phone: bool = False  # the site owner's own number (--form-phone)

    @classmethod
    def new(cls, phone: str | None = None) -> Canaries:
        """``phone``: the owner's own number (ten digits) instead of the made-up one, for
        forms whose mask takes only numbers starting with 9."""
        token = "".join(secrets.choice(_ALNUM) for _ in range(10))
        secret = "".join(secrets.choice(_ALNUM) for _ in range(10))
        surname = "".join(
            secrets.choice(_CONSONANTS) + secrets.choice(_VOWELS) for _ in range(4)
        ).capitalize()
        return cls(
            email=f"suveren.{token}@example.com",
            phone=phone or "100" + "".join(secrets.choice("0123456789") for _ in range(7)),
            password=f"Sv-{secret}!",
            name=f"Тест {surname}",
            own_phone=bool(phone),
        )

    def shown(self) -> dict[str, str]:
        """The values for the report; the owner's own number is not written out."""
        values = self.values()
        if self.own_phone:
            values["phone"] = self.phone[:3] + "*****" + self.phone[-2:]
        return values

    def values(self) -> dict[str, str]:
        return {"name": self.name, "phone": self.phone, "email": self.email,
                "password": self.password}  # fmt: skip

    def needles(self) -> dict[str, list[tuple[str, str]]]:
        """kind -> (how it is written, lower-case text to look for)."""
        surname = self.name.split()[-1].lower()
        token = self.email.split("@")[0].split(".")[-1]
        secret = self.password[3:-1]
        email = self.email.lower()
        phones = [p + self.phone for p in ("7", "+7", "8", "")]
        result: dict[str, list[tuple[str, str]]] = {
            "email": [(PLAIN, email), (PLAIN, token)],
            "password": [(PLAIN, secret)],
            "name": [(PLAIN, surname)],
            "phone": [],
        }
        for kind, texts in (
            ("email", [email]),
            ("phone", phones),
            ("name", [surname]),
            ("password", [self.password]),
        ):
            for text in texts:
                for algo, label in (("md5", "MD5"), ("sha1", "SHA-1"), ("sha256", "SHA-256")):
                    digest = hashlib.new(algo, text.encode("utf-8")).hexdigest()
                    result[kind].append((f"в виде хеша {label}", digest))
        for kind, text in (("email", email), ("password", secret), ("name", surname)):
            result[kind] += [(BASE64, b) for b in _base64_forms(text.encode("utf-8"))]
        return result

    def phone_pattern(self) -> re.Pattern[str]:
        """The phone with any separators a mask puts in, after an optional +7 or 8."""
        sep = r"[\s\-().]{0,3}"
        core = sep.join(self.phone)
        return re.compile(rf"(?<!\d)(?:\+?[78]{sep})?{core}(?!\d)")


def own_phone(text: str) -> str:
    """The ten digits of a Russian mobile number given as +7 9xx..., 8 9xx... or 9xx...;
    raises ValueError otherwise."""
    digits = "".join(c for c in text if c.isdigit())
    if len(digits) == 11 and digits[0] in "78":
        digits = digits[1:]
    if len(digits) != 10 or not digits.startswith("9"):
        raise ValueError(f"--form-phone: «{text}» не похож на мобильный номер (+7 9XX XXX-XX-XX)")
    return digits


def _base64_forms(data: bytes) -> list[str]:
    """``data`` in base64 at each of the three offsets it can have inside a longer
    encoded text, without the edge characters that depend on the neighbours."""
    forms = []
    for pad in range(3):
        encoded = base64.b64encode(b"\0" * pad + data).decode("ascii").rstrip("=")
        start = (pad * 8 + 5) // 6 if pad else 0
        end = len(encoded) - (1 if (pad + len(data)) % 3 else 0)
        piece = encoded[start:end]
        if len(piece) >= 8:
            forms += [piece.lower(), piece.replace("+", "-").replace("/", "_").lower()]
    return list(dict.fromkeys(forms))


def views(data: bytes, depth: int = 0) -> Iterator[tuple[str, str]]:
    """The texts a payload may hide a value in, lower-case: as is, URL-decoded, with
    JSON \\u escapes undone, unpacked from gzip/zlib, and base64 pieces decoded."""
    how = PLAIN if depth == 0 else BASE64
    unpacked = _unpack(data)
    if unpacked is not None:
        data, how = unpacked, (PACKED if depth == 0 else BASE64)
    text = data.decode("utf-8", "replace")
    yield how, text.lower()
    once = unquote_plus(text)
    if once != text:
        yield how, once.lower()
        twice = unquote_plus(once)
        if twice != once:
            yield how, twice.lower()
    if "\\u" in text:
        yield how, _JSON_ESCAPE.sub(lambda m: chr(int(m[1], 16)), once).lower()
    if depth == 0:
        for token in _B64_TOKEN.findall(once)[:400]:
            raw = _b64decode(token)
            if raw:
                yield from views(raw, depth + 1)


def _unpack(data: bytes) -> bytes | None:
    for opener in (
        (lambda d: gzip.decompress(d)) if data[:2] == b"\x1f\x8b" else None,
        (lambda d: zlib.decompressobj().decompress(d, _MAX_UNPACKED))
        if data[:1] == b"\x78"
        else None,
    ):
        if opener is not None:
            with contextlib.suppress(OSError, EOFError, zlib.error):
                unpacked = opener(data)
                if unpacked:
                    return unpacked[:_MAX_UNPACKED]
    return None


def _b64decode(token: str) -> bytes:
    token = token.rstrip("=")
    with contextlib.suppress(binascii.Error, ValueError):
        return base64.b64decode(token.replace("-", "+").replace("_", "/") + "=" * (-len(token) % 4))
    return b""


@dataclass(frozen=True, slots=True)
class Leak:
    page: str  # the page where the value was typed
    kind: str  # name, phone, email, password
    host: str
    method: str
    url: str  # the request, shortened
    how: str  # PLAIN, PACKED, BASE64 or a hash

    def to_dict(self) -> dict[str, str]:
        return {"page": self.page, "kind": self.kind, "host": self.host,
                "method": self.method, "url": self.url, "how": self.how}  # fmt: skip


def find_leaks(probe: FormProbe, canaries: Canaries) -> list[Leak]:
    """Every request of ``probe`` that carries a value typed into a field, one leak per
    host, kind and form of writing."""
    typed = {f["kind"] for f in probe.filled if f.get("value")}
    needles = {k: v for k, v in canaries.needles().items() if k in typed}
    phone = canaries.phone_pattern() if "phone" in typed else None
    found: dict[tuple[str, str, str], Leak] = {}
    for sent in probe.sent:
        host = (urlsplit(sent.url).hostname or "").lower()
        for kind, how in _search(sent, needles, phone):
            key = (host, kind, how)
            if key not in found:
                found[key] = Leak(
                    probe.final_url or probe.url, kind, host, sent.method, _short(sent.url), how
                )
    return list(found.values())


def _search(
    sent: Sent, needles: dict[str, list[tuple[str, str]]], phone: re.Pattern[str] | None
) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    payloads = [sent.url.encode("utf-8")] + ([sent.body] if sent.body else [])
    for payload in payloads:
        for view_how, text in views(payload):
            for kind, items in needles.items():
                for how, needle in items:
                    if needle in text:
                        how = view_how if how in (PLAIN, BASE64) and view_how != PLAIN else how
                        hits.append((kind, how))
                        break
            if phone is not None and phone.search(text):
                hits.append(("phone", view_how))
    return list(dict.fromkeys(hits))


def _short(url: str, limit: int = 140) -> str:
    return url if len(url) <= limit else url[: limit - 1] + "…"


@dataclass(slots=True)
class FormLeaks:
    """What the experiment saw, for the check and report.facts["form_leaks"]."""

    pages: list[FormProbe] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    leaks: list[Leak] = field(default_factory=list)  # to third parties
    own: list[Leak] = field(default_factory=list)  # to the site itself, before sending
    hosts: dict[str, HostInfo] = field(default_factory=dict)

    @property
    def filled(self) -> list[dict[str, Any]]:
        return [f for p in self.pages for f in p.filled if f.get("value")]

    def to_dict(self, canaries: Canaries) -> dict[str, Any]:
        def recipient(host: str) -> dict[str, Any]:
            info = self.hosts.get(host)
            return {
                "service": info.service if info else None,
                "country": info.country if info else None,
                "foreign": info.foreign if info else None,
            }

        return {
            "values": canaries.shown(),
            "watch_seconds": (FORM_WATCH_MS + FORM_FLUSH_MS) // 1000,
            "pages": [
                {
                    "url": p.final_url or p.url,
                    "fields": [
                        {
                            "kind": f["kind"],
                            "label": f["label"],
                            "visible": f["visible"],
                            "typed": bool(f.get("value")),
                        }
                        for f in p.filled
                    ],
                    "submits_stopped": p.submits,
                }
                for p in self.pages
            ],
            "errors": self.errors,
            "leaks": [{**leak.to_dict(), **recipient(leak.host)} for leak in self.leaks],
            "own": [leak.to_dict() for leak in self.own],
        }


def _kinds(kinds: set[str]) -> str:
    return ", ".join(KIND_RU[k] for k in KIND_ORDER if k in kinds)


def _pages(n: int) -> str:
    if n % 10 == 1 and n % 100 != 11:
        return f"{n} странице"
    return f"{n} страницах"


def _fields(n: int) -> str:
    if n % 10 == 1 and n % 100 != 11:
        return f"{n} поле"
    if n % 10 in (2, 3, 4) and n % 100 not in (12, 13, 14):
        return f"{n} поля"
    return f"{n} полей"


def leak_check(r: FormLeaks) -> Check:
    if not r.pages:
        reason = r.errors[0] if r.errors else "браузер не открыл страницы"
        return Check(GROUP_152, TITLE, Status.UNKNOWN, f"Не проверено: {reason}.")
    filled = r.filled
    typed = {f["kind"] for f in filled}
    # Phones the mask turned into another number were erased (render.fill_forms).
    masked = "phone" not in typed and any(f["kind"] == "phone" for p in r.pages for f in p.filled)
    mask = MASK_NOTE if masked else ""
    if not filled:
        return Check(
            GROUP_152,
            TITLE,
            Status.UNKNOWN,
            f"Не проверено: на {_pages(len(r.pages))} не нашлось полей для имени, телефона, "
            "почты или пароля, в которые можно ввести текст." + mask,
        )
    watch = (FORM_WATCH_MS + FORM_FLUSH_MS) // 1000
    done = (
        f"В {_fields(len(filled))} ({_kinds(typed)}) на {_pages(len(r.pages))} ввели "
        f"тестовые данные и {watch} секунд смотрели, что уходит со страницы. Формы не "
        "отправлялись." + mask
    )
    own = ""
    if r.own:
        own = (
            f" Сам сайт получает введённое ещё до отправки ({_kinds({x.kind for x in r.own})}):"
            f" {r.own[0].method} {r.own[0].url}."
        )
    if not r.leaks:
        return Check(
            GROUP_152,
            TITLE,
            Status.OK,
            f"{done} Сторонние сервисы введённое не получили.{own} Видно то, что уходит "
            "открытым текстом, в base64, в сжатом виде или как хеш; зашифрованное "
            "распознать нельзя.",
            law=LAW,
        )
    by_host: dict[str, list[Leak]] = {}
    for leak in r.leaks:
        by_host.setdefault(leak.host, []).append(leak)
    lines = []
    foreign: list[str] = []
    for host, leaks in list(by_host.items())[:SHOWN]:
        info = r.hosts.get(host)
        who = info.label() if info else host
        if info is not None and info.foreign:
            foreign.append(who)
        kinds = {x.kind for x in leaks}
        hows = ", ".join(dict.fromkeys(x.how for x in leaks))
        first = leaks[0]
        lines.append(
            f"{who} — {_kinds(kinds)} ({hows}); запрос {first.method} {first.url}, "
            f"страница {_path(first.page)}"
        )
    if len(by_host) > SHOWN:
        lines.append(f"и ещё {len(by_host) - SHOWN}")
    password = any(x.kind == "password" for x in r.leaks)
    status = Status.FAIL if password or foreign else Status.WARN
    details = (
        f"{done} Введённое ещё до отправки получили сторонние сервисы: "
        + "; ".join(lines)
        + "."
        + own
    )
    return Check(GROUP_152, TITLE, status, details, _advice(r, foreign, password), law=LAW)


def _path(url: str) -> str:
    parts = urlsplit(url)
    return parts.path or "/"


def _advice(r: FormLeaks, foreign: list[str], password: bool) -> str:
    text = (
        "Посетитель ещё не нажал «Отправить» и не дал согласия, а его данные уже у третьих "
        "лиц: раскрывать персональные данные третьим лицам без согласия нельзя (152-ФЗ, "
        "ст. 7), поручить их обработку другому лицу можно только с согласия (ст. 6 ч. 3)."
    )
    if foreign:
        text += (
            f" Получатель за рубежом ({', '.join(foreign)}) — это ещё и трансграничная "
            "передача (ст. 12)."
        )
    if password:
        text += (
            " Пароль уходит стороннему сервису: это уже не только закон, но и прямой риск "
            "захвата учётных записей. Исключите поле пароля из записи сессий и проверьте, "
            "какой скрипт его читает."
        )
    services = {(r.hosts[x.host].service or "") for x in r.leaks if x.host in r.hosts}
    metrika = any("Метрик" in s for s in services)
    text += (
        " Запретите сторонним скриптам читать поля форм: в записи сессий отключите "
        "сохранение введённого текста"
        + (
            " (в Яндекс Метрике — опция Вебвизора «Записывать все поля» или класс "
            "ym-disable-keys на полях)"
            if metrika
            else ""
        )
        + ", в рекламных пикселях — автоматический сбор данных из форм; или подключайте "
        "такие сервисы только после согласия посетителя."
    )
    return text


def pages_with_fields(
    home: str, pages: list[tuple[str, str]], login: str | None = None
) -> list[str]:
    """The home page, the sign-in page (its password field matters most, and a script
    often draws it, so its HTML is not asked) and the inner pages whose HTML has a
    personal-data or password field, up to MAX_PAGES. ``pages`` is (url, html)."""
    chosen = [home]
    if login and login != home:
        chosen.append(login)
    for url, html in pages:
        if len(chosen) >= MAX_PAGES:
            break
        if url not in chosen and _HAS_FIELD.search(html):
            chosen.append(url)
    return chosen


_HAS_FIELD = re.compile(
    r"<input\b[^>]*\btype=[\"']?(?:email|tel|password)\b"
    r"|<input\b[^>]*\bname=[\"']?[^\"'>]*(?:phone|email|name|fio)",
    re.I,
)


async def run_form_leaks(
    urls: list[str],
    site: str,
    collector: Any,
    *,
    timeout: float = 25.0,
    canaries: Canaries | None = None,
    phone: str | None = None,
) -> tuple[Check, FormLeaks, dict[str, Any]]:
    """Type test values into the forms of ``urls`` (the first is the home page) and
    report which third parties received them. Returns the check, the details and the
    facts for the JSON report."""
    from suveren.render import BrowserSession

    canaries = canaries or Canaries.new(phone)
    result = FormLeaks()
    async with BrowserSession(timeout=timeout) as session:
        for url in urls[:MAX_PAGES]:
            try:
                result.pages.append(await session.fill_forms(url, canaries.values()))
            except ModuleError as exc:
                result.errors.append(str(exc))
    landed = {registrable_domain(urlsplit(p.final_url).hostname or "") for p in result.pages} - {""}
    leaks = [leak for p in result.pages for leak in find_leaks(p, canaries)]
    own_domains = {registrable_domain(site), *landed}
    result.own = [x for x in leaks if registrable_domain(x.host) in own_domains]
    result.leaks = [x for x in leaks if registrable_domain(x.host) not in own_domains]
    if result.leaks:
        result.hosts = await classify([x.url for x in result.leaks], site, collector, tuple(landed))
    return leak_check(result), result, result.to_dict(canaries)
