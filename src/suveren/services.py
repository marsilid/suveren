"""The service database: how to recognise a provider and where it is based.

Each :class:`Service` lists every trace it can leave:

* ``ns`` / ``mx`` — host suffixes of name servers and mail exchangers
  (``*`` is a wildcard: ``*awsdns-*`` matches ``ns-12.awsdns-34.com``);
* ``asn`` / ``as_names`` — the network an IP address belongs to (hosting, CDN);
* ``registrar`` / ``issuer`` — substrings of the registrar or TLS issuer name;
* ``page`` — regular expressions searched in the page HTML (lowercased),
  for scripts, fonts and widgets. Such services also set ``category``.

``country`` is the provider's jurisdiction, not the location of a data centre:
sanctions follow the company. To add a service, append it below and add a test.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from suveren.models import Category, Severity
from suveren.utils import host_matches

META_NOTE = (
    "Meta Platforms признана в России экстремистской организацией, Facebook и Instagram "
    "заблокированы."
)


@dataclass(frozen=True)
class Service:
    name: str
    country: str
    category: Category | None = None
    ns: tuple[str, ...] = ()
    mx: tuple[str, ...] = ()
    asn: tuple[int, ...] = ()
    as_names: tuple[str, ...] = ()
    cdn: bool = False
    registrar: tuple[str, ...] = ()
    issuer: tuple[str, ...] = ()
    page: tuple[str, ...] = ()
    severity: Severity | None = None
    note: str = ""
    alternative: str = ""
    _page_re: tuple[re.Pattern[str], ...] = field(default=(), init=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_page_re", tuple(re.compile(p) for p in self.page))

    @property
    def foreign(self) -> bool:
        return self.country != "RU"


def _infra() -> list[Service]:
    return [
        # --- Foreign infrastructure -------------------------------------------------
        Service(
            "Cloudflare",
            "US",
            ns=("ns.cloudflare.com",),
            asn=(13335, 209242),
            as_names=("cloudflare",),
            cdn=True,
            registrar=("cloudflare",),
        ),
        Service(
            "Amazon Web Services",
            "US",
            ns=("*awsdns-*",),
            mx=("amazonaws.com",),
            asn=(16509, 14618),
            as_names=("amazon",),
            registrar=("amazon registrar",),
        ),
        Service("Google Workspace", "US", mx=("google.com", "googlemail.com")),
        Service(
            "Google Cloud",
            "US",
            ns=("googledomains.com",),
            asn=(15169, 396982, 19527),
            as_names=("google",),
        ),
        Service("Microsoft 365", "US", mx=("mail.protection.outlook.com", "outlook.com")),
        Service(
            "Microsoft Azure",
            "US",
            ns=("azure-dns.com", "azure-dns.net", "azure-dns.org", "azure-dns.info"),
            asn=(8075,),
            as_names=("microsoft",),
        ),
        Service(
            "DigitalOcean",
            "US",
            ns=("digitalocean.com",),
            asn=(14061,),
            as_names=("digitalocean",),
        ),
        Service(
            "GoDaddy",
            "US",
            ns=("domaincontrol.com",),
            mx=("secureserver.net",),
            asn=(26496, 398101),
            as_names=("godaddy",),
            registrar=("godaddy",),
        ),
        Service(
            "Namecheap",
            "US",
            ns=("registrar-servers.com",),
            mx=("registrar-servers.com", "privateemail.com"),
            registrar=("namecheap",),
            note="В 2022 году Namecheap прекратил обслуживать клиентов из России.",
        ),
        Service(
            "Hetzner",
            "DE",
            ns=("hetzner.com", "hetzner.de", "your-server.de"),
            mx=("your-server.de",),
            asn=(24940, 213230),
            as_names=("hetzner",),
        ),
        Service(
            "OVHcloud",
            "FR",
            ns=("ovh.net",),
            mx=("ovh.net",),
            asn=(16276,),
            as_names=("ovh",),
            registrar=("ovh",),
        ),
        Service(
            "Hostinger",
            "LT",
            ns=("dns-parking.com",),
            mx=("hostinger.com",),
            asn=(47583,),
            as_names=("hostinger",),
            registrar=("hostinger",),
        ),
        Service(
            "IONOS",
            "DE",
            ns=("ui-dns.com", "ui-dns.de", "ui-dns.org", "ui-dns.biz"),
            mx=("ionos.com", "ionos.de", "kundenserver.de"),
            asn=(8560,),
            registrar=("ionos", "1&1"),
        ),
        Service("Gandi", "FR", ns=("gandi.net",), mx=("gandi.net",), registrar=("gandi",)),
        Service("NS1", "US", ns=("nsone.net",)),
        Service("Vercel", "US", ns=("vercel-dns.com",), as_names=("vercel",)),
        Service(
            "Wix",
            "IL",
            Category.BUILDER,
            ns=("wixdns.net",),
            asn=(58182,),
            as_names=("wix",),
            page=(r"static\.wixstatic\.com", r"static\.parastorage\.com"),
        ),
        Service(
            "Tilda",
            "AE",
            Category.BUILDER,
            as_names=("tilda",),
            page=(r"tildacdn\.(?:com|pro|one|net)", r"tilda-blocks"),
            note="Tilda создана российской командой, но её сеть зарегистрирована на компанию "
            "в ОАЭ.",
        ),
        Service(
            "Webflow",
            "US",
            Category.BUILDER,
            page=(r"assets\.website-files\.com", r"cdn\.prod\.website-files\.com"),
        ),
        Service(
            "Squarespace",
            "US",
            Category.BUILDER,
            page=(r"static1\.squarespace\.com", r"squarespace-cdn\.com"),
        ),
        Service("Shopify", "CA", Category.BUILDER, page=(r"cdn\.shopify\.com",)),
        Service("Framer", "NL", Category.BUILDER, page=(r"framerusercontent\.com",)),
        Service(
            "Akamai",
            "US",
            ns=("akam.net",),
            asn=(20940, 16625),
            as_names=("akamai",),
            cdn=True,
        ),
        Service("Akamai Linode", "US", asn=(63949,), as_names=("linode",)),
        Service("Fastly", "US", asn=(54113,), as_names=("fastly",), cdn=True),
        Service("Vultr", "US", asn=(20473,), as_names=("vultr", "choopa")),
        Service("Contabo", "DE", asn=(51167,), as_names=("contabo",)),
        Service("Leaseweb", "NL", asn=(60781, 16265, 28753), as_names=("leaseweb",)),
        Service("Gcore", "LU", asn=(199524,), as_names=("gcore", "g-core"), cdn=True),
        Service("Imperva", "US", asn=(19551,), as_names=("incapsula", "imperva"), cdn=True),
        Service("Sucuri", "US", asn=(30148,), as_names=("sucuri",), cdn=True),
        Service("Zoho Mail", "IN", mx=("zoho.com", "zoho.eu", "zohomail.com")),
        Service("Proton Mail", "CH", mx=("protonmail.ch",)),
        Service("Mailgun", "US", mx=("mailgun.org",)),
        Service("SendGrid", "US", mx=("sendgrid.net",)),
        Service("Mimecast", "GB", mx=("mimecast.com",)),
        Service("Proofpoint", "US", mx=("pphosted.com", "ppe-hosted.com")),
        Service("Barracuda", "US", mx=("barracudanetworks.com",)),
        Service("iCloud Mail", "US", mx=("mail.icloud.com",)),
        Service("Fastmail", "AU", mx=("messagingengine.com",)),
        Service("Yahoo Mail", "US", mx=("yahoodns.net",)),
        Service("Broadcom MessageLabs", "US", mx=("messagelabs.com",)),
        Service("DNS Made Easy", "US", ns=("dnsmadeeasy.com",), as_names=("tiggee",)),
        Service("NetActuate", "US", as_names=("netactuate",)),
        # Registrars that leave no other trace.
        Service("Tucows", "CA", registrar=("tucows",)),
        Service("Porkbun", "US", registrar=("porkbun",)),
        Service("Name.com", "US", registrar=("name.com",)),
        Service("Network Solutions", "US", registrar=("network solutions",)),
        Service("Dynadot", "US", registrar=("dynadot",)),
        Service("eNom", "US", registrar=("enom",)),
        Service("MarkMonitor", "US", registrar=("markmonitor",)),
        Service("1API", "DE", registrar=("1api",)),
        Service("Internet Domain Service BS", "BS", registrar=("internet domain service bs",)),
        Service("Squarespace Domains", "US", registrar=("squarespace", "google llc")),
        Service("PDR (PublicDomainRegistry)", "IN", registrar=("publicdomainregistry", "pdr ltd")),
        # --- Russian infrastructure -------------------------------------------------
        Service("Координационный центр доменов .RU/.РФ", "RU", registrar=("cc-ru", "cc-rf")),
        Service(
            "Яндекс 360",
            "RU",
            ns=("yandex.net", "yandex.ru"),
            mx=("yandex.net", "yandex.ru"),
        ),
        Service(
            "Yandex Cloud",
            "RU",
            ns=("yandexcloud.net",),
            asn=(13238, 200350),
            as_names=("yandex",),
        ),
        Service("VK WorkSpace (Mail.ru)", "RU", ns=("mail.ru",), mx=("mail.ru",)),
        Service("VK Cloud", "RU", asn=(47764, 47541), as_names=("vk-", "vkontakte", "mail-ru")),
        Service(
            "Selectel",
            "RU",
            ns=("selectel.org", "selectel.ru"),
            asn=(49505, 50340),
            as_names=("selectel",),
        ),
        Service(
            "Timeweb",
            "RU",
            ns=("timeweb.ru", "timeweb.org"),
            mx=("timeweb.ru",),
            asn=(9123,),
            as_names=("timeweb",),
            registrar=("timeweb",),
        ),
        Service(
            "Beget",
            "RU",
            ns=("beget.com", "beget.pro", "beget.ru"),
            mx=("beget.com",),
            asn=(198610,),
            as_names=("beget",),
            registrar=("beget",),
        ),
        Service(
            "REG.RU",
            "RU",
            ns=("reg.ru",),
            mx=("reg.ru",),
            asn=(197695,),
            as_names=("reg.ru", "regru"),
            registrar=("regru", "reg.ru"),
        ),
        Service(
            "RU-CENTER",
            "RU",
            ns=("nic.ru",),
            mx=("nic.ru",),
            asn=(48287,),
            registrar=("ru-center", "rucenter", "nic.ru"),
        ),
        Service("R01", "RU", registrar=("r01",)),
        Service("Регтайм (Webnames)", "RU", registrar=("regtime", "webnames")),
        Service("Наунет", "RU", registrar=("naunet",)),
        Service("Salenames", "RU", registrar=("salenames",)),
        Service("SpaceWeb", "RU", ns=("sweb.ru",), mx=("sweb.ru",), as_names=("spaceweb",)),
        Service("SprintHost", "RU", ns=("sprinthost.ru",), as_names=("sprinthost",)),
        Service("Джино", "RU", ns=("jino.ru",), mx=("jino.ru",)),
        Service("Мастерхост", "RU", ns=("masterhost.ru",), as_names=("masterhost",)),
        Service("Хостлэнд", "RU", ns=("hostland.ru",), mx=("hostland.ru",)),
        Service("FirstVDS", "RU", ns=("firstvds.ru",), as_names=("firstvds",)),
        Service(
            "DDoS-Guard",
            "RU",
            ns=("ddos-guard.net",),
            asn=(57724,),
            as_names=("ddos-guard",),
            cdn=True,
        ),
        Service("Qrator", "RU", asn=(200449,), as_names=("qrator",), cdn=True),
        Service("NGENIX", "RU", as_names=("ngenix",), cdn=True),
        Service("Servicepipe", "RU", as_names=("servicepipe",), cdn=True),
        Service("Ростелеком", "RU", asn=(12389,), as_names=("rostelecom",)),
        Service("МТС", "RU", asn=(8359,), as_names=("mts pjsc",)),
    ]


def _tls() -> list[Service]:
    commercial = Severity.MEDIUM
    return [
        Service("Let's Encrypt", "US", issuer=("let's encrypt",)),
        Service("Google Trust Services", "US", issuer=("google trust services",)),
        Service("Amazon Trust Services", "US", issuer=("amazon",)),
        Service("ZeroSSL", "AT", issuer=("zerossl",)),
        Service("Sectigo", "GB", issuer=("sectigo", "comodo"), severity=commercial),
        Service(
            "DigiCert",
            "US",
            issuer=("digicert", "geotrust", "thawte", "rapidssl"),
            severity=commercial,
        ),
        Service("GlobalSign", "BE", issuer=("globalsign",), severity=commercial),
        Service("Entrust", "US", issuer=("entrust",), severity=commercial),
        Service("SSL.com", "US", issuer=("ssl corporation", "ssl.com"), severity=commercial),
        Service("GoDaddy (УЦ)", "US", issuer=("godaddy", "starfield"), severity=commercial),
        Service("НУЦ Минцифры", "RU", issuer=("russian trusted",)),
    ]


def _page() -> list[Service]:
    c = Category
    return [
        # --- Analytics --------------------------------------------------------------
        Service(
            "Google Analytics / Tag Manager",
            "US",
            c.ANALYTICS,
            page=(r"googletagmanager\.com", r"google-analytics\.com"),
            alternative="Заменить на Яндекс Метрику.",
        ),
        Service(
            "Meta Pixel (Facebook)",
            "US",
            c.ANALYTICS,
            page=(r"connect\.facebook\.net/[^\"']*fbevents", r"fbq\("),
            severity=Severity.MEDIUM,
            note=META_NOTE,
            alternative="Заменить на пиксель VK Рекламы или Яндекс Метрику.",
        ),
        Service(
            "Hotjar",
            "MT",
            c.ANALYTICS,
            page=(r"static\.hotjar\.com",),
            alternative="Заменить на Вебвизор в Яндекс Метрике.",
        ),
        Service(
            "Microsoft Clarity",
            "US",
            c.ANALYTICS,
            page=(r"clarity\.ms",),
            alternative="Заменить на Вебвизор в Яндекс Метрике.",
        ),
        Service("Mixpanel", "US", c.ANALYTICS, page=(r"cdn\.mxpnl\.com", r"api\.mixpanel\.com")),
        Service("Amplitude", "US", c.ANALYTICS, page=(r"cdn\.amplitude\.com",)),
        Service("Segment", "US", c.ANALYTICS, page=(r"cdn\.segment\.(?:com|io)",)),
        Service("Plausible", "EE", c.ANALYTICS, page=(r"plausible\.io/js",)),
        Service(
            "LinkedIn Insight",
            "US",
            c.ANALYTICS,
            page=(r"snap\.licdn\.com",),
            note="LinkedIn заблокирован в России с 2016 года.",
        ),
        Service(
            "X (Twitter) Pixel",
            "US",
            c.ANALYTICS,
            page=(r"static\.ads-twitter\.com",),
            note="X (Twitter) заблокирован в России.",
        ),
        Service(
            "TikTok Pixel", "SG", c.ANALYTICS, page=(r"analytics\.tiktok\.com", r"tiktokw\.us")
        ),
        Service("Microsoft Bing Ads", "US", c.ANALYTICS, page=(r"bat\.bing\.com",)),
        Service("Pinterest Tag", "US", c.ANALYTICS, page=(r"s\.pinimg\.com/ct",)),
        Service(
            "Cloudflare Web Analytics",
            "US",
            c.ANALYTICS,
            page=(r"static\.cloudflareinsights\.com",),
        ),
        Service(
            "Sentry", "US", c.ANALYTICS, page=(r"browser\.sentry-cdn\.com", r"ingest\.sentry\.io")
        ),
        Service("Mindbox", "RU", c.ANALYTICS, page=(r"api\.mindbox\.ru", r"api\.s\.mindbox\.ru")),
        Service("Яндекс Метрика", "RU", c.ANALYTICS, page=(r"mc\.yandex\.(?:ru|com)",)),
        Service("Top.Mail.ru", "RU", c.ANALYTICS, page=(r"top-fwz1\.mail\.ru", r"top\.mail\.ru")),
        Service("Пиксель VK", "RU", c.ANALYTICS, page=(r"vk\.com/rtrg",)),
        Service("LiveInternet", "RU", c.ANALYTICS, page=(r"counter\.yadro\.ru",)),
        Service("Rambler Top100", "RU", c.ANALYTICS, page=(r"counter\.rambler\.ru",)),
        Service("Roistat", "RU", c.ANALYTICS, page=(r"cloud\.roistat\.com",)),
        Service("Calltouch", "RU", c.ANALYTICS, page=(r"mod\.calltouch\.ru",)),
        Service("CoMagic", "RU", c.ANALYTICS, page=(r"app\.comagic\.ru",)),
        # --- Ads ----------------------------------------------------------------------
        Service(
            "Google Ads / AdSense",
            "US",
            c.ADS,
            page=(r"googleadservices\.com", r"googlesyndication\.com", r"doubleclick\.net"),
            note="Google прекратил показ рекламы в России в 2022 году.",
        ),
        Service("Criteo", "FR", c.ADS, page=(r"static\.criteo\.net",)),
        Service("Рекламная сеть Яндекса", "RU", c.ADS, page=(r"an\.yandex\.ru", r"yandex\.ru/ads")),
        Service("Adfox", "RU", c.ADS, page=(r"ads\.adfox\.ru",)),
        Service("AdRiver", "RU", c.ADS, page=(r"adriver\.ru",)),
        Service("VK Реклама", "RU", c.ADS, page=(r"ad\.mail\.ru", r"ads\.vk\.com")),
        Service("МТС Ads", "RU", c.ADS, page=(r"\.a\.mts\.ru", r"ads\.mts\.ru")),
        # --- Site builders and CMS (Russian) ---------------------------------------------
        Service("1С-Битрикс", "RU", c.BUILDER, page=(r"/bitrix/(?:js|templates|cache)/",)),
        Service("Nethouse", "RU", c.BUILDER, page=(r"nethouse\.ru",)),
        Service("LPgenerator", "RU", c.BUILDER, page=(r"lpgenerator\.ru",)),
        Service("InSales", "RU", c.BUILDER, page=(r"insales\.ru", r"insales-cdn\.com")),
        # --- Captcha ------------------------------------------------------------------
        Service(
            "Google reCAPTCHA",
            "US",
            c.CAPTCHA,
            page=(r"google\.com/recaptcha", r"recaptcha\.net", r"gstatic\.com/recaptcha"),
        ),
        Service("hCaptcha", "US", c.CAPTCHA, page=(r"hcaptcha\.com/1/api", r"js\.hcaptcha\.com")),
        Service(
            "Cloudflare Turnstile",
            "US",
            c.CAPTCHA,
            page=(r"challenges\.cloudflare\.com/turnstile",),
        ),
        Service(
            "Yandex SmartCaptcha",
            "RU",
            c.CAPTCHA,
            page=(r"smartcaptcha\.yandexcloud\.net", r"captcha-api\.yandex\.ru"),
        ),
        # --- Fonts --------------------------------------------------------------------
        Service(
            "Google Fonts", "US", c.FONTS, page=(r"fonts\.googleapis\.com", r"fonts\.gstatic\.com")
        ),
        Service("Adobe Fonts", "US", c.FONTS, page=(r"use\.typekit\.net", r"p\.typekit\.net")),
        Service(
            "Font Awesome", "US", c.FONTS, page=(r"kit\.fontawesome\.com", r"use\.fontawesome\.com")
        ),
        Service("Bunny Fonts", "SI", c.FONTS, page=(r"fonts\.bunny\.net",)),
        # --- JS libraries from a CDN ----------------------------------------------------
        Service("jsDelivr", "PL", c.JS_CDN, page=(r"cdn\.jsdelivr\.net",)),
        Service("unpkg", "US", c.JS_CDN, page=(r"unpkg\.com",)),
        Service("cdnjs (Cloudflare)", "US", c.JS_CDN, page=(r"cdnjs\.cloudflare\.com",)),
        Service("Google Hosted Libraries", "US", c.JS_CDN, page=(r"ajax\.googleapis\.com",)),
        Service("jQuery CDN", "US", c.JS_CDN, page=(r"code\.jquery\.com",)),
        Service(
            "BootstrapCDN",
            "US",
            c.JS_CDN,
            page=(r"(?:stackpath|maxcdn|netdna)\.bootstrapcdn\.com",),
        ),
        Service(
            "polyfill.io",
            "CN",
            c.JS_CDN,
            page=(r"polyfill\.io",),
            severity=Severity.HIGH,
            note="В 2024 году домен polyfill.io перешёл к новому владельцу и начал раздавать "
            "вредоносный код. Скрипт нужно удалить немедленно.",
            alternative="Удалить скрипт: современным браузерам полифиллы не нужны.",
        ),
        Service("Yandex CDN (yastatic)", "RU", c.JS_CDN, page=(r"yastatic\.net",)),
        Service("Яндекс (прочие ресурсы)", "RU", c.JS_CDN, page=(r"\.yandex\.net",)),
        Service(
            "VK / Mail.ru (прочие ресурсы)",
            "RU",
            c.JS_CDN,
            # Static and SDK hosts only: plain links to vk.com or e.mail.ru are not resources.
            page=(
                r"(?:st\d*|static|privacy-cs|img\d*|imgs\d*)\.mail\.ru",
                r"\.userapi\.com",
                r"\.okcdn\.ru",
                r"(?:st|static|sun\d+-\d+)\.vk\.(?:com|ru)",
            ),
        ),
        # --- Chats and widgets ------------------------------------------------------------
        Service("Intercom", "US", c.CHAT, page=(r"widget\.intercom\.io", r"js\.intercomcdn\.com")),
        Service("Zendesk", "US", c.CHAT, page=(r"static\.zdassets\.com",)),
        Service("Drift", "US", c.CHAT, page=(r"js\.driftt\.com",)),
        Service("tawk.to", "US", c.CHAT, page=(r"embed\.tawk\.to",)),
        Service("Crisp", "FR", c.CHAT, page=(r"client\.crisp\.chat",)),
        Service("LiveChat", "PL", c.CHAT, page=(r"cdn\.livechatinc\.com",)),
        Service("Tidio", "PL", c.CHAT, page=(r"code\.tidio\.co",)),
        Service("HubSpot", "US", c.CHAT, page=(r"js\.hs-scripts\.com", r"js\.hsforms\.net")),
        Service("Jivo", "RU", c.CHAT, page=(r"code\.jivosite\.com", r"code\.jivo\.ru")),
        Service(
            "Битрикс24", "RU", c.CHAT, page=(r"bitrix24\.\w+/upload/crm", r"cdn-ru\.bitrix24\.ru")
        ),
        Service("Carrot quest", "RU", c.CHAT, page=(r"cdn\.carrotquest\.(?:app|io)",)),
        Service("Talk-Me", "RU", c.CHAT, page=(r"lcab\.talk-me\.ru",)),
        Service("Callibri", "RU", c.CHAT, page=(r"cdn\.callibri\.ru",)),
        Service("Envybox", "RU", c.CHAT, page=(r"cdn\.envybox\.io",)),
        Service("Marquiz", "RU", c.CHAT, page=(r"script\.marquiz\.ru", r"marquiz\.ru/v2")),
        Service("amoCRM", "RU", c.CHAT, page=(r"gso\.amocrm\.ru", r"forms\.amocrm\.ru")),
        Service("Яндекс Формы", "RU", c.CHAT, page=(r"forms\.yandex\.ru",)),
        Service(
            "Google Forms",
            "US",
            c.CHAT,
            page=(r"docs\.google\.com/forms",),
            note="Ответы в форме хранятся на серверах Google за рубежом.",
            alternative="Заменить на Яндекс Формы или форму на собственном сайте.",
        ),
        Service("Typeform", "ES", c.CHAT, page=(r"embed\.typeform\.com",)),
        Service("Calendly", "US", c.CHAT, page=(r"assets\.calendly\.com",)),
        Service("OneSignal (push)", "US", c.CHAT, page=(r"cdn\.onesignal\.com",)),
        # --- Maps ---------------------------------------------------------------------------
        Service(
            "Google Maps",
            "US",
            c.MAPS,
            page=(r"maps\.googleapis\.com", r"google\.com/maps/embed"),
        ),
        Service("Mapbox", "US", c.MAPS, page=(r"api\.mapbox\.com",)),
        Service(
            "Яндекс Карты", "RU", c.MAPS, page=(r"api-maps\.yandex\.ru", r"yandex\.ru/map-widget")
        ),
        Service("2ГИС", "RU", c.MAPS, page=(r"maps\.api\.2gis\.ru", r"widgets\.2gis\.com")),
        # --- Video --------------------------------------------------------------------------
        Service(
            "YouTube",
            "US",
            c.VIDEO,
            page=(
                r"youtube\.com/embed/",
                r"youtube-nocookie\.com/embed",
                r"youtube\.com/iframe_api",
            ),
            severity=Severity.MEDIUM,
            note="Работа YouTube в России сильно замедлена с 2024 года: у большинства "
            "посетителей встроенное видео не воспроизводится.",
        ),
        Service("Vimeo", "US", c.VIDEO, page=(r"player\.vimeo\.com/video",)),
        Service("RUTUBE", "RU", c.VIDEO, page=(r"rutube\.ru/play/embed",)),
        Service(
            "VK Видео", "RU", c.VIDEO, page=(r"vk\.com/video_ext\.php", r"vkvideo\.ru/video_ext")
        ),
        # --- Payments -----------------------------------------------------------------------
        Service("Stripe", "US", c.PAYMENTS, page=(r"js\.stripe\.com",)),
        Service("PayPal", "US", c.PAYMENTS, page=(r"paypal\.com/sdk/js", r"paypalobjects\.com")),
        Service("ЮKassa", "RU", c.PAYMENTS, page=(r"yookassa\.ru", r"yoomoney\.ru/checkout")),
        Service("CloudPayments", "RU", c.PAYMENTS, page=(r"widget\.cloudpayments\.ru",)),
        Service("Т-Касса", "RU", c.PAYMENTS, page=(r"securepay\.tinkoff\.ru",)),
        Service("Robokassa", "RU", c.PAYMENTS, page=(r"auth\.robokassa\.ru",)),
        # --- Sign-in ------------------------------------------------------------------------
        Service(
            "Google Sign-In",
            "US",
            c.AUTH,
            page=(r"accounts\.google\.com/gsi/client", r"apis\.google\.com/js/platform\.js"),
        ),
        Service("Sign in with Apple", "US", c.AUTH, page=(r"appleid\.cdn-apple\.com",)),
        Service("Auth0", "US", c.AUTH, page=(r"cdn\.auth0\.com",)),
        Service("VK ID", "RU", c.AUTH, page=(r"id\.vk\.com", r"@vkid/sdk")),
        Service("Яндекс ID", "RU", c.AUTH, page=(r"yastatic\.net/s3/passport-sdk",)),
        # --- Social widgets -----------------------------------------------------------------
        Service(
            "Facebook SDK",
            "US",
            c.SOCIAL,
            page=(r"connect\.facebook\.net/[a-z_]+/(?:sdk|all)\.js",),
            severity=Severity.MEDIUM,
            note=META_NOTE,
        ),
        Service(
            "Instagram embed",
            "US",
            c.SOCIAL,
            page=(r"instagram\.com/embed\.js",),
            severity=Severity.MEDIUM,
            note=META_NOTE,
        ),
        Service(
            "X (Twitter) widgets",
            "US",
            c.SOCIAL,
            page=(r"platform\.twitter\.com/widgets\.js",),
            note="X (Twitter) заблокирован в России.",
        ),
        Service("Виджеты VK", "RU", c.SOCIAL, page=(r"vk\.com/js/api/openapi\.js",)),
        Service("Виджеты Одноклассников", "RU", c.SOCIAL, page=(r"connect\.ok\.ru",)),
    ]


INFRA_SERVICES: tuple[Service, ...] = tuple(_infra())
TLS_SERVICES: tuple[Service, ...] = tuple(_tls())
PAGE_SERVICES: tuple[Service, ...] = tuple(_page())
ALL_SERVICES: tuple[Service, ...] = INFRA_SERVICES + TLS_SERVICES + PAGE_SERVICES
_WITH_PAGE_PATTERNS = tuple(s for s in ALL_SERVICES if s.page)

# Top-level domains run by Russian registries.
RU_ZONES = frozenset(
    {"ru", "su", "xn--p1ai", "xn--p1acf", "moscow", "xn--80adxhks", "tatar", "xn--d1acj3b"}
)
# Common generic zones: (registry, country of the registry operator).
GENERIC_ZONES: dict[str, tuple[str, str]] = {
    "com": ("Verisign", "US"),
    "net": ("Verisign", "US"),
    "org": ("Public Interest Registry", "US"),
    "info": ("Identity Digital", "US"),
    "biz": ("GoDaddy Registry", "US"),
    "io": ("Identity Digital", "US"),
    "app": ("Google Registry", "US"),
    "dev": ("Google Registry", "US"),
    "xyz": ("XYZ.com", "US"),
    "online": ("Radix", "AE"),
    "site": ("Radix", "AE"),
    "store": ("Radix", "AE"),
    "tech": ("Radix", "AE"),
    "space": ("Radix", "AE"),
    "website": ("Radix", "AE"),
    "pro": ("Identity Digital", "US"),
    "shop": ("GMO Registry", "JP"),
    "co": (".CO Internet", "CO"),
    "me": ("doMEn", "ME"),
    "ai": ("Government of Anguilla", "AI"),
}
_CCTLD_COUNTRY_FIX = {"uk": "GB", "eu": "EU"}


def zone_info(domain: str) -> tuple[str, str | None]:
    """Return (zone description, registry country or None if unknown)."""
    tld = domain.rsplit(".", 1)[-1].lower()
    shown = "." + (tld.encode("ascii").decode("idna") if tld.startswith("xn--") else tld)
    if tld in RU_ZONES:
        return f"{shown} — Координационный центр доменов .RU/.РФ", "RU"
    if tld in GENERIC_ZONES:
        registry, country = GENERIC_ZONES[tld]
        return f"{shown} — {registry}", country
    if len(tld) == 2 and tld.isalpha():
        return shown, _CCTLD_COUNTRY_FIX.get(tld, tld.upper())
    return shown, None


def by_ns(host: str) -> Service | None:
    return next((s for s in INFRA_SERVICES if any(host_matches(host, p) for p in s.ns)), None)


def by_mx(host: str) -> Service | None:
    return next((s for s in INFRA_SERVICES if any(host_matches(host, p) for p in s.mx)), None)


def by_network(asn: int | None, as_name: str | None) -> Service | None:
    if asn is not None:
        for s in INFRA_SERVICES:
            if asn in s.asn:
                return s
    name = (as_name or "").lower()
    if name:
        for s in INFRA_SERVICES:
            if any(marker in name for marker in s.as_names):
                return s
    return None


def by_registrar(registrar: str | None) -> Service | None:
    name = (registrar or "").lower()
    if not name:
        return None
    return next((s for s in INFRA_SERVICES if any(m in name for m in s.registrar)), None)


def by_issuer(issuer: str | None) -> Service | None:
    name = (issuer or "").lower()
    if not name:
        return None
    return next((s for s in TLS_SERVICES if any(m in name for m in s.issuer)), None)


def scan_page(html: str) -> list[tuple[Service, str]]:
    """Find page-level services in the HTML; returns (service, matched text) pairs."""
    text = html.lower()
    found: list[tuple[Service, str]] = []
    for service in _WITH_PAGE_PATTERNS:
        for regex in service._page_re:
            match = regex.search(text)
            if match:
                found.append((service, match.group(0)))
                break
    return found
