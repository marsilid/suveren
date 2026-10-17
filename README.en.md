<div align="center">

# Suveren

**Website and company audit for doing business in Russia: foreign dependencies, personal-data law, blocking, company registry and sanctions.**

[![CI](https://github.com/marsilid/suveren/actions/workflows/ci.yml/badge.svg)](https://github.com/marsilid/suveren/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%E2%80%933.14-blue)
![License](https://img.shields.io/badge/license-MIT-green)

[Русская версия](README.md)

</div>

Suveren answers six questions:

1. **What breaks if foreign providers cut you off?** It finds everything running on
   infrastructure outside Russia (DNS, mail, hosting, CDN, site builder, registrar, TLS
   certificate, page scripts and widgets), explains the risk, suggests a Russian alternative and
   grades independence from **A** to **F**.
2. **Does the site comply with Federal Law 152-FZ and is it reachable from Russia?** Privacy
   policy (with a checklist of the sections Roskomnadzor recommends), consent in forms and whether
   it is drawn up separately from offers and user agreements (required since 1 September 2025), cookie notice, cross-border transfer, data localisation, the
   Roskomnadzor register of personal-data operators and the Roskomnadzor block list. It also
   flags sign-in through Google, Apple, Facebook and other foreign services: since 1 December
   2023 Russian sites may authorise users in Russia only by a Russian phone number, Gosuslugi,
   the biometric system or Russian-owned providers (Federal Law 149-FZ, art. 8 part 10), and
   since 7 July 2026 this is fined under art. 13.55 of the Code of Administrative Offences.
   Above the 152-FZ section the report estimates the maximum fines (Code of Administrative
   Offences, art. 13.11 and 13.55) for the problems found, per legal entity, sole trader and
   official; possible offences are listed but not added up. It is an estimate of the maximum
   risk, not legal advice; JSON has it in the `fines` field.
3. **Can someone forge a letter from the company's domain?** SPF, DMARC, DKIM and MTA-STS
   records, summed up as a plain verdict: yes, partly or no.
4. **Are there forgotten subdomains someone could take over?** Subdomains from Certificate
   Transparency logs, checked for CNAMEs to deleted projects or to unregistered domains.
5. **Whose code runs on the site, and how well are visitors protected?** Third-party scripts,
   abandoned or compromised script domains, SRI, CSP, HSTS, cookie flags and TLS.
6. **Who is behind it?** Company data from the Russian state register (EGRUL) and screening of
   the company and its head against the US (OFAC SDN), EU and UK sanctions lists.

The tool targets Russian businesses, so its interface and reports are in Russian.

![Terminal output](docs/demo.svg)

## Install and run

```bash
pip install "suveren[browser] @ git+https://github.com/marsilid/suveren.git"

suveren scan example.ru --browser    # full check, page rendered in Edge/Chrome
suveren scan example.ru --quick      # foreign dependencies only (handy in CI)
suveren batch sites.txt              # many sites: index.html, CSV, a report per site
suveren company 7707083893           # company by tax ID (INN), OGRN or domain
suveren diff before.json after.json
suveren update                       # refresh sanctions and block lists
```

On Windows you can also run `Suveren.bat`, which installs everything on first launch. A
`Dockerfile` is included.

![HTML report](docs/report-screenshot.png)

![Company check](docs/company-screenshot.png)

## How it works

- A service's country is the jurisdiction of the company that runs it: sanctions apply to
  companies, not data centres. The database has 180+ foreign and Russian services.
- Each category with a foreign dependency yields one finding: high −20, medium −10, low −4.
  A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, otherwise F. A Russian server next to a foreign one in the
  same category lowers the risk one step.
- The mail verdict follows what receivers enforce: DMARC `p=reject` means a forged From: is
  rejected, `quarantine` or `pct` < 100 sends it to spam, `p=none` or no DMARC lets it through.
  SPF is checked for a single record, `+all`/`?all` and the 10-lookup limit across all includes;
  DKIM keys are looked up under common selectors and a miss is reported as "not verified".
- Subdomain takeover uses the [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)
  fingerprints (CC BY 4.0). A CNAME to a domain missing from DNS counts as "anyone can buy it"
  only if the registry (RDAP, WHOIS for .ru) confirms it is free: registered but undelegated
  domains are common. Every hit says "possible takeover, verify manually".
- Web security asks for SRI only on public library CDNs (analytics scripts change constantly and
  can't have it), flags CSP `'unsafe-inline'` only without a nonce or hash, and skips header checks
  when a bot wall answered or the site redirected to another domain. TLS is probed on the host you
  asked for, not on a redirect target (yandex.ru → sso.passport.yandex.ru).
- `--browser` renders the home page with Playwright in the installed Edge or Chrome and counts
  every network request, so tag-manager-injected scripts are found too. Anti-bot stubs and empty
  JavaScript shells are detected and reported as "not verified" rather than as failures.
- Sanctions matching by INN/OGRN is exact. Name matching is transliteration-aware
  ("СБЕРБАНК РОССИИ" = "Sberbank of Russia"). Matches on a person's name are flagged as possible,
  because namesakes exist.
- DNS goes through the system resolver. If it looks filtered, Yandex DNS over TLS is used, and
  only if that fails too, Google and Cloudflare DNS-over-HTTPS (the report says so). `--dns ru`
  never sends the checked names abroad.
- All sources are public and free: Team Cymru IP-to-ASN, RDAP/WHOIS, egrul.nalog.ru,
  pd.rkn.gov.ru, the Roskomnadzor register dump from antifilter.download, and the official OFAC,
  EU and UK lists. Lists are cached for a day.

## Limitations

The home page and up to 6 inner pages (`--pages`, contacts and order pages first) are analysed; some sites block
even the browser mode; a site behind a CDN hides its real hosting; name-based sanctions matches
need human review. The scan is passive. The report is a triage aid, **not legal advice**.

## Contributing

Services live in [`src/suveren/services.py`](src/suveren/services.py): add a `Service(...)`
entry, add a test to `tests/test_services.py`, and open a pull request. Tests run offline.

## License

[MIT](LICENSE)
