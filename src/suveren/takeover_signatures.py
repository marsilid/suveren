"""Services whose abandoned custom domains can be claimed by someone else.

Source: "Can I take over XYZ?" by EdOverflow and contributors,
https://github.com/EdOverflow/can-i-take-over-xyz (fingerprints.json, CC BY 4.0),
checked 2026-10-17. Only entries marked "Vulnerable" or "Edge case" are used. Where the
source gives no CNAME, the service's standard custom-domain target is filled in.
Entries marked ``added`` are not in the source and were added by Suveren; fingerprints
after a "# seen" comment are the placeholder texts these services showed on 2026-10-17,
kept next to the source's older wording.

``fingerprint`` is a regular expression searched in the page the subdomain serves,
``HTTP_STATUS=n`` means the status code, and ``nxdomain`` means the CNAME target
itself no longer exists.
"""

from __future__ import annotations

from dataclasses import dataclass

SOURCE_URL = "https://github.com/EdOverflow/can-i-take-over-xyz"


@dataclass(frozen=True, slots=True)
class Signature:
    service: str
    cnames: tuple[str, ...]  # suffixes of the CNAME target
    fingerprints: tuple[str, ...] = ()
    nxdomain: bool = False
    vulnerable: bool = True  # False: "Edge case" in the source, takeover is not always possible
    added: bool = False


SIGNATURES: tuple[Signature, ...] = (
    Signature("AWS Elastic Beanstalk", ("elasticbeanstalk.com",), nxdomain=True),
    Signature(
        "AWS S3",
        ("amazonaws.com",),
        ("The specified bucket does not exist",),
    ),
    Signature("Agile CRM", ("agilecrm.com",), ("Sorry, this page is no longer available.",)),
    Signature("Айри (Airee.ru)", ("airee.ru",), ("Ошибка 402. Сервис Айри.рф не оплачен",)),
    Signature("Anima", ("animaapp.io",), ("The page you were looking for does not exist.",)),
    Signature("Bitbucket", ("bitbucket.io",), ("Repository not found",)),
    Signature("Campaign Monitor", ("createsend.com",), ("Trying to access your account\\?",)),
    Signature(
        "Canny",
        ("canny.io",),
        ("Company Not Found", "There is no such company. Did you enter the right URL\\?"),
    ),
    Signature("Cargo Collective", ("cargocollective.com",), ("404 Not Found",)),
    Signature("Discourse", ("trydiscourse.com",), nxdomain=True),
    Signature(
        "Frontify",
        ("frontify.com",),
        ("404 - Page Not Found", "Oops… looks like you got lost"),
        vulnerable=False,
    ),
    Signature("Gemfury", ("furyns.com",), ("404: This page could not be found.",)),
    Signature(
        "Ghost",
        ("ghost.io",),
        ("Site unavailable\\.", "Failed to resolve DNS path for this host"),
    ),
    Signature(
        "GitHub Pages",
        ("github.io",),
        ("There isn't a GitHub Pages site here.",),
        vulnerable=False,
    ),
    Signature("Help Juice", ("helpjuice.com",), ("We could not find what you're looking for.",)),
    Signature("Help Scout", ("helpscoutdocs.com",), ("No settings were found for this company:",)),
    Signature("Helprace", ("helprace.com",), ("HTTP_STATUS=301",)),
    Signature("Heroku", ("herokuapp.com", "herokudns.com"), ("No such app",), vulnerable=False),
    Signature(
        "Intercom",
        ("custom.intercom.help",),
        ("Uh oh. That page doesn't exist.",),
        vulnerable=False,
    ),
    Signature("JetBrains YouTrack", ("youtrack.cloud",), ("is not a registered InCloud YouTrack",)),
    Signature("LaunchRock", ("launchrock.com",), ("HTTP_STATUS=500",)),
    Signature(
        "Microsoft Azure",
        (
            "cloudapp.net",
            "cloudapp.azure.com",
            "azurewebsites.net",
            "blob.core.windows.net",
            "azure-api.net",
            "azurehdinsight.net",
            "azureedge.net",
            "azurecontainer.io",
            "database.windows.net",
            "azuredatalakestore.net",
            "search.windows.net",
            "azurecr.io",
            "redis.cache.windows.net",
            "servicebus.windows.net",
            "visualstudio.com",
            "trafficmanager.net",
        ),
        nxdomain=True,
    ),
    Signature(
        "Netlify", ("netlify.app", "netlify.com"), ("Not Found - Request ID:",), vulnerable=False
    ),
    Signature("Ngrok", ("ngrok.io",), ("Tunnel .*.ngrok.io not found",)),
    Signature(
        "Pantheon",
        ("pantheonsite.io",),
        ("404 error unknown site!", "404 - Unknown site"),  # seen
    ),
    Signature("Pingdom", ("stats.pingdom.com",), ("Sorry, couldn't find the status page",)),
    Signature(
        "Readme.io",
        ("readme.io",),
        ("The creators of this project are still working on making everything perfect!",),
    ),
    Signature(
        "Read the Docs",
        ("readthedocs.io",),
        (
            "The link you have followed or the URL that you entered does not exist.",
            "The project you requested does not exist or may have been removed",  # seen
        ),
    ),
    Signature(
        "Shopify",
        ("myshopify.com",),
        (
            "Sorry, this shop is currently unavailable.",
            "This store is currently unavailable.",  # seen
        ),
        vulnerable=False,
    ),
    Signature("Strikingly", ("strikinglydns.com",), ("PAGE NOT FOUND.",)),
    Signature("Surge.sh", ("surge.sh",), ("project not found",)),
    Signature("SurveySparrow", ("surveysparrow.com",), ("Account not found.",)),
    Signature("Tilda", ("tilda.ws",), ("Please renew your subscription",), vulnerable=False),
    Signature(
        "Tumblr",
        ("domains.tumblr.com",),
        ("Whatever you were looking for doesn't currently exist at this address",),
        vulnerable=False,
    ),
    Signature(
        "Uberflip", ("read.uberflip.com",), ("The URL you've accessed does not provide a hub.",)
    ),
    Signature("UptimeRobot", ("stats.uptimerobot.com",), ("page not found",)),
    Signature(
        "Vercel", ("vercel-dns.com", "vercel.app"), ("DEPLOYMENT_NOT_FOUND",), vulnerable=False
    ),
    Signature(
        "Webflow",
        ("proxy-ssl.webflow.com", "proxy.webflow.com"),
        ("The page you are looking for doesn't exist or has been moved.",),
        vulnerable=False,
    ),
    Signature(
        "Wix",
        ("wixdns.net",),
        ("Looks Like This Domain Isn't Connected To A Website Yet!",),
        vulnerable=False,
    ),
    Signature(
        "WordPress.com", ("wordpress.com",), ("Do you want to register .*.wordpress.com\\?",)
    ),
    Signature(
        "Worksites",
        ("worksites.net",),
        ("Hello! Sorry, but the website you&rsquo;re looking for doesn&rsquo;t exist.",),
    ),
    # Bucket names are global, as in AWS S3: a deleted bucket's name can be taken again.
    Signature(
        "Yandex Object Storage",
        ("website.yandexcloud.net", "storage.yandexcloud.net"),
        ("NoSuchBucket",),
        vulnerable=False,
        added=True,
    ),
)


def find_signature(targets: list[str]) -> Signature | None:
    """The service any of the CNAME targets points to, if it is a known one."""
    for target in targets:
        host = target.lower().rstrip(".")
        for sig in SIGNATURES:
            if any(host == s or host.endswith("." + s) for s in sig.cnames):
                return sig
    return None
