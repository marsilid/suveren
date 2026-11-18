<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/logo-dark.png">
  <img alt="Suveren" src="docs/logo-light.png" width="300">
</picture>

**Website and company audit for doing business in Russia**<br>
foreign dependencies · personal-data law (152-FZ) · blocking · mail spoofing · web security · company registry and sanctions

[![Release](https://img.shields.io/github/v/release/marsilid/suveren)](https://github.com/marsilid/suveren/releases/latest)
[![PyPI](https://img.shields.io/pypi/v/suveren)](https://pypi.org/project/suveren/)
[![CI](https://github.com/marsilid/suveren/actions/workflows/ci.yml/badge.svg)](https://github.com/marsilid/suveren/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%E2%80%933.14-blue)
![License](https://img.shields.io/badge/license-AGPL--3.0-blue)

[Website (in Russian)](https://marsilid.github.io/suveren/) · [Русская версия](README.md)

</div>

Give it a website and in under a minute you get a report: what on the site depends on foreign
services, which legal requirements are broken and what fine that can mean, whether mail can be
forged in the company's name, and what to fix first. Every finding comes with its evidence: a DNS
record, a response header, a quote from the privacy policy, a script address. The report helps
set priorities and is not a legal opinion.

It helps business owners and IT directors, web studios, lawyers and personal-data officers,
procurement departments checking counterparties.

The tool, its reports and the guide are in Russian: the audience is Russian businesses.

![Suveren in the terminal](docs/demo.svg)

<sub>The pictures show made-up sites and a company in the reserved `.test` zone, from the
project's test lab ([`tests/lab.py`](tests/lab.py)): the real checks, but no one else's data.</sub>

## Quick start

**Windows.** Download `Suveren.exe` from the
[latest release](https://github.com/marsilid/suveren/releases/latest) and run it: a menu opens, no
command line and no Python needed. Windows may warn about an unknown publisher — "More info" →
"Run anyway".

![Suveren menu](docs/menu.svg)

**Any system** (Python 3.11+):

```bash
python3 -m pip install "suveren[browser]"
suveren scan example.ru
```

On Windows write `py` instead of `python3`. Install exactly through `python3 -m pip`: a bare
`pip` command is sometimes from an old Python 2 or 3.8. If pip says `Could not find a version
that satisfies the requirement suveren` ("from versions: none"), its Python is older than 3.11:
check `python3 --version` and upgrade Python, or download the ready exe.

<details>
<summary>Other ways: from source and Docker</summary>

From source, `Suveren.bat` opens the same menu: download the repository (Code → Download ZIP),
unpack it and run the batch file — on first launch it installs everything it needs.

```bash
docker build -t suveren https://github.com/marsilid/suveren.git
docker run --rm -v "$PWD:/work" suveren scan example.ru
```

</details>

## What it checks

- **What breaks with the next round of sanctions?** DNS, mail, hosting, CDN, site builder,
  registrar, certificate, scripts and widgets. An independence grade from A to F and a migration
  plan.
- **Does the site comply with 152-FZ?** The privacy policy and its contents, consent in forms,
  cookies and whether refusing them works (in the browser), cross-border transfer, the register
  of personal-data operators, Google and Apple sign-in, Instagram and Facebook links without the
  note that Meta is banned, ad labelling. The total of possible administrative fines.
- **Does the site open in Russia?** The domain and IPs in the block list, blocked services on the
  pages.
- **Can mail be forged in the company's name?** SPF, DMARC, DKIM, MTA-STS and a plain answer:
  yes, partly or no. Also: does the SPF allow addresses anyone can rent in a public cloud.
- **Are there forgotten subdomains that can be taken over?**
- **Whose code runs on the site?** Third-party and abandoned scripts, vulnerable libraries, keys
  in the code, security headers, cookies, TLS, CAA and DNSSEC.
- **Who are we dealing with?** The company in the state register (EGRUL), US, EU, UK and UN
  sanctions lists, the Rosfinmonitoring list.

About 70 checks with permanent IDs ([list](docs/checks.md)) and a database of 300+ services.
Findings from different sections combine into attack scenarios: "mail can be forged" + "the site
takes payments" = phishing in the company's name.

## The report

The report is saved to `reports/` and opens in the browser. On top: grades, fines and what to fix
first; under each problem — the evidence, the article of law and how to fix it. It can also be
saved as PDF or Word, as a one-page summary for management, or under your studio's brand.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/report-dark.png">
  <img alt="HTML report" src="docs/report-light.png">
</picture>

<details>
<summary>The 152-FZ section, the company check and a summary over a list of sites</summary>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/compliance-dark.png">
  <img alt="152-FZ check" src="docs/compliance-light.png">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/company-dark.png">
  <img alt="Company check" src="docs/company-light.png">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/batch-dark.png">
  <img alt="Summary over a list of sites" src="docs/batch-light.png">
</picture>

</details>

## Main commands

```bash
suveren scan site.ru                    # regular audit, about 20 seconds
suveren scan site.ru --profile deep     # deep: browser, up to 12 pages, service cut-off
suveren scan site.ru --pdf report.pdf   # plus PDF; --docx for Word, --summary for management
suveren company 7700990010              # a company by INN, OGRN or website
suveren batch sites.txt                 # a list of sites: summary table, CSV, a report each
suveren watch sites.txt --every 24h     # watch sites; changes can go to Telegram
suveren research sites.txt              # a study: only the share of sites with each finding
suveren diff old.json new.json          # what changed between two audits
suveren draft report.json               # a draft policy or consent: show it to a lawyer
suveren menu                            # the menu, no command line
suveren scan site.ru -v                 # every network step with timings: see where it hangs
suveren scan site.ru --dkim-selector ew # also check your own DKIM selector, not just common ones
suveren scan site.ru --proxy http://proxy:3128  # behind a corporate proxy
```

All commands and options are in the [guide](docs/guide.md#все-команды) (in Russian) and in
`suveren --help` and `suveren scan --help`.

## What Suveren does to the site

Mostly Suveren looks at what any visitor sees: public DNS records, open registers and the site's
pages. No port scanning, no password guessing.

- **`company` by INN or OGRN** never contacts the site: only the state register, other registers
  and sanctions lists. Given a website, it opens the home page to find the INN there.
- **`scan`** opens the home page and up to 6 inner pages. In two places it probes: it tries the
  outdated TLS 1.0 and 1.1 and opens pages of subdomains that point to external services. The
  site sees your IP, as with a normal visit.
- **`--browser` and `--profile deep`** open pages in a browser, so the site's JavaScript runs on
  your computer. The browser is sandboxed and cannot reach your network or download files.
- **`--own-site`** goes deeper on **your own** site: `.git` and `.env` files, TLS ciphers, mail
  servers, and with `--form-leaks` data leaking from forms. It runs only after ownership is
  proven (`suveren verify`).

For every check, [docs/checks.md](docs/checks.md) says what it does to the site and what the
person running it risks. Where data goes with `--dns ru` is in the
[guide](docs/guide.md#параметры-проверки); the risks of plugins are in
[docs/plugins.md](docs/plugins.md).

## In CI

```bash
suveren scan example.ru --no-open --sarif suveren.sarif --fail-on fail
```

SARIF is read by GitHub and GitLab code scanning and DefectDojo. A finding you decided not to fix
yet can be accepted in `.suveren-ignore` with a reason, an author and a deadline: it stays in the
report but does not fail the build, and counts again after the deadline. More in the
[guide](docs/guide.md#ci-и-другие-инструменты).

## Data sources and limitations

All sources are open and free, no API keys: DNS, RDAP and WHOIS, the state register, the register
of personal-data operators, the block list export by antifilter.download, certificate
transparency logs, sanctions lists, the retire.js vulnerability database, the server-location
database [IP Geolocation by DB-IP](https://db-ip.com) (CC BY 4.0, downloaded once a month).
`suveren doctor` checks that they all answer.

The report helps set priorities and **is not a legal opinion**: every 152-FZ check links to the
article of law. Where a check could not be done, Suveren says "not checked" rather than a false
"OK". All limitations are in the [guide](docs/guide.md#ограничения).

## How it differs from online checkers

Online 152-FZ checkers are convenient: nothing to install, and for a fee they often offer
document templates and a lawyer's advice. Suveren works differently:

| | Suveren | Online 152-FZ services |
|---|---|---|
| Where it runs | on your computer or in CI | on the service's server |
| Code | open (AGPL), you can see how each check works | not published |
| Price | free, no sign-up | short summary free, detailed report paid |
| What it checks | 152-FZ, plus foreign dependencies (DNS, mail, hosting, CDN), mail spoofing (SPF, DKIM, DMARC), the block list, site security, the company in the state register and sanctions lists | mostly 152-FZ: documents, forms, cookies, third-party scripts, where the server is |
| For a team | JSON, SARIF, `--fail-on` for CI, checking a list of sites | a report on the service's site |
| Accuracy | every check has a permanent ID, answers verified on the [lab](docs/accuracy.md) | the method is usually not published |

What Suveren lacks: a lawyer's advice. It drafts a policy and a consent from what it found on
the site, but they need finishing and a lawyer's review. The report is not a legal opinion.

## Written about

- [The author's article on Habr](https://habr.com/ru/articles/1105240/) (in Russian) on how
  Suveren works and what it checks.
- [News on Anti-Malware.ru](https://www.anti-malware.ru/news/2026-11-09-111332/51972) (in
  Russian), 9 November 2026.

## Contributing

Adding a service to the database needs no programming: it is the data file
[`services.json`](src/suveren/data/services.json), described in the
[guide](docs/guide.md#как-добавить-сервис-в-базу). Or just open an "Add a service" issue. How the
code is organised and how to run the tests is in [CONTRIBUTING.md](CONTRIBUTING.md);
vulnerabilities go by the rules in [SECURITY.md](SECURITY.md).

## License

[GNU AGPL-3.0](LICENSE) or later, from version 1.1: the code is open, and any modified version,
including one run as a service, must be open too. A commercial license is available for closed
products and SaaS — see [COPYRIGHT](COPYRIGHT). Versions up to 1.0.x remain under MIT.

Related project: [ReconLens](https://github.com/marsilid/reconlens) — passive OSINT
reconnaissance of a domain with a security score.
