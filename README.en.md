<div align="center">

# Suveren

**Website and company audit for doing business in Russia**<br>
foreign dependencies · personal-data law (152-FZ) · blocking · mail spoofing · web security · company registry and sanctions

[![CI](https://github.com/marsilid/suveren/actions/workflows/ci.yml/badge.svg)](https://github.com/marsilid/suveren/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%E2%80%933.14-blue)
![License](https://img.shields.io/badge/license-AGPL--3.0-blue)

[Русская версия](README.md)

</div>

Give it a website address and a minute later you have a report: what on the site depends on
foreign providers, which legal requirements are broken and what fine that can bring, whether
someone can send mail in the company's name, and what to fix first. Every finding comes with
its evidence: the DNS record, the response header, the quote from the privacy policy, the
script URL.

Suveren mostly looks at what any visitor can see: public DNS records, open registries and the
site's pages. No port scanning, no password guessing, no hunting for exposed `.git` or `.env`.
What each check does to the site and what you risk by running it is
[below](#what-suveren-does-to-the-site).

The tool, its reports and the detailed guide are in Russian, as is the law it checks against.

![Suveren in a terminal](docs/demo.svg)

<sub>The pictures show made-up sites in the reserved `.test` zone: real audit data with names,
addresses and IPs replaced, so no real company is shown.</sub>

## What it checks

| | Question | What is looked at |
|---|---|---|
| 🌍 | **What breaks with the next wave of sanctions?** | DNS, mail, hosting, CDN, site builder, registrar, TLS certificate, page scripts and widgets. An independence grade from **A** to **F** and a migration plan to Russian providers |
| ⚖️ | **Does the site comply with 152-FZ?** | the privacy policy and its contents, consent in forms, cookies, cross-border transfer, data localisation, the register of personal-data operators, sign-in through Google and Apple, recommendation technologies. The total of possible fines under the Code of Administrative Offences |
| 🚫 | **Is the site reachable from Russia?** | the domain and IP addresses in Roskomnadzor's block list, blocked services on the pages |
| ✉️ | **Can mail be forged in the company's name?** | SPF, DMARC, DKIM and its key length, MTA-STS and a plain answer: yes, partly or no |
| 🔓 | **Are there forgotten subdomains someone could take over?** | subdomains from Certificate Transparency logs that point to deleted projects on third-party services |
| 🛡️ | **Whose code runs on the site?** | third-party and abandoned script domains, vulnerable library versions, keys in code, CSP, HSTS, cookies, TLS, CAA and DNSSEC |
| 🏢 | **Who are we dealing with?** | the company in the state register (EGRUL), US (SDN), EU and UK sanctions lists, plus UN and OFAC non-SDN, the Rosfinmonitoring list, the register of personal-data operators |

About 70 checks and a database of 300+ services, each with a permanent ID — see [docs/checks.md](docs/checks.md).
Findings from different sections are combined into **attack scenarios**: for example "mail can
be forged" + "the site takes payments" = phishing in the company's name.

## What Suveren does to the site

Every check carries two labels (in [docs/checks.md](docs/checks.md) and `suveren checks ID`):
what it does to the site and what the person running it risks.

| Run | To the site | For you |
|---|---|---|
| `suveren company` by INN or OGRN | no contact: only the state register, the RKN register and sanctions lists | the site does not see you |
| `scan --profile quick` | only looks: the home page and DNS | the site sees your IP, as on any visit |
| `scan` (default) | looks at the home page, up to 6 inner pages and the MTA-STS file. It **probes** in two places: it tries the outdated TLS 1.0 and 1.1, and it opens subdomain pages that point to outside services or to cloud addresses | the site sees your IP; such connections may show up in its security logs |
| `--browser`, `--cutoff`, `--profile deep` | the same, but a browser opens the pages | **the site's JavaScript runs** in a browser on your computer. The browser cannot reach your local network or save files, but the scripts run as for any visitor |
| `--own-site` (after `suveren verify`) | **probes your own site**: `.git` and `.env`, weak TLS ciphers, STARTTLS of the mail servers | only for a site whose ownership is proven by a TXT record or a file; never in batch |
| `--own-site --form-leaks` | **types test values** into forms and never sends them | the site's JavaScript runs. Never runs without proven ownership |
| `--plugin file.py` | whatever the plugin does | **the plugin's code runs with your rights**: use only plugins you trust |

Mail checks, the block register and certificate logs do not contact the site, but every `scan`
still opens the home page: the foreign services are read from it. `--dns ru` sends DNS queries
through Yandex DNS, but only DNS: the site's name still goes to the certificate logs (crt.sh,
Cert Spotter, for the subdomain check) and to rdap.org, and IP addresses to Team Cymru (USA).

## How to run it

### Windows: double click

Download `Suveren.exe` from [Releases](https://github.com/marsilid/suveren/releases) and run it.
No Python needed. Windows may warn about an unknown publisher: click "More info" → "Run anyway".
The exe is built from this code by GitHub Actions.

It opens a menu, so no command line is needed:

![Suveren menu](docs/menu.svg)

From the source code, `Suveren.bat` opens the same menu: download the repository
(Code → Download ZIP), unpack it and run the batch file. On first launch it installs everything
it needs ([Python 3.11+](https://www.python.org/downloads/) required).

### Any system

```bash
pip install "suveren[browser]"
suveren scan example.ru
```

### Docker

```bash
docker build -t suveren https://github.com/marsilid/suveren.git
docker run --rm -v "$PWD:/work" suveren scan example.ru
```

## The report

The report is saved to `reports/` and opens in the browser. At the top: the grades, the total of
possible fines and what to do first; under every problem: the evidence, the article of law and
how to fix it.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/report-dark.png">
  <img alt="HTML report" src="docs/report-light.png">
</picture>

The 152-FZ section: every check links to its article of law and names the possible fine.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/compliance-dark.png">
  <img alt="152-FZ checks" src="docs/compliance-light.png">
</picture>

## Commands

| Command | What it does |
|---|---|
| `suveren scan site.ru` | full website audit |
| `suveren batch sites.txt` | audit a list of sites: summary table, CSV and a report per site |
| `suveren company <INN, OGRN or site>` | state register, sanctions lists, register of personal-data operators |
| `suveren diff old.json new.json` | what changed between two audits |
| `suveren checks [ID or tag]` | all checks with their IDs and tags |
| `suveren services [filter]` | the database of recognised services |
| `suveren update` | download fresh sanctions lists and the block list |
| `suveren doctor` | check that every data source answers |
| `suveren audit reports/` | do reports contradict themselves |
| `suveren unknown` | external domains missing from the service database |
| `suveren watch sites.txt --every 24h` | watch sites: audit again and report what changed |
| `suveren draft report.json` | a draft privacy policy or consent from the findings (check it with a lawyer) |
| `suveren verify site.ru` | prove the site is yours, for `--own-site` and `--form-leaks` |
| `suveren menu` | the menu (same as double-clicking the exe) |

Main `scan` options:

| Option | What it does |
|---|---|
| `--browser`, `-b` | open the site in a browser (Edge or Chrome) to see scripts loaded at runtime |
| `--profile quick\|standard\|deep` | `quick` — foreign services only; `standard` — all checks (default); `deep` — in a browser, up to 12 pages, with the `--cutoff` experiment |
| `--checks mail,SUV-LAW-001` | only the checks you need: by ID, prefix or tag |
| `--pages N` | how many inner pages to check besides the home page (default 6) |
| `--cutoff` | experiment: open the site with foreign services cut off and show what breaks |
| `--form-leaks` | experiment: do form fields reach third parties before submission (only with `--own-site`, after `suveren verify`) |
| `--own-site` | own-site mode: `.git` and `.env`, TLS ciphers, mail STARTTLS (after `suveren verify`) |
| `--pdf file.pdf` | also save the report as PDF |
| `--brand-name`, `--brand-logo`, `--brand-url` | the report under your agency's brand |
| `--json file.json`, `--sarif file.sarif` | results for `diff`, CI and security scanners |
| `--since previous.json` | what changed since the previous audit |
| `--fail-under C`, `--fail-on fail` | non-zero exit code for CI |
| `--ignore file` | accepted findings with a reason, an author and an end date (default `.suveren-ignore`) |
| `--dns ru` | DNS queries through Yandex DNS only. Other sources stay the same: the site's name goes to crt.sh, Cert Spotter and rdap.org, IP addresses to Team Cymru |
| `--no-mail`, `--no-security`, `--no-subdomains`, `--no-152fz`, `--no-blocklist` | skip a section |

The full list is in `suveren scan --help`; every check is described in the
[guide](docs/guide.md) (in Russian).

## Company check

```bash
suveren company 7707083893      # by INN (tax number)
suveren company 1027700132195   # by OGRN (registration number)
suveren company example.ru      # the INN is found on the site
```

State register data (status, registration date, head), the company and its head screened
against US, EU, UK and UN sanctions lists, the Rosfinmonitoring list, the register of personal-data operators and a cross-check
with the website. Matches by INN and OGRN are exact; matches by name are possible matches to be
checked by hand.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/company-dark.png">
  <img alt="Company check" src="docs/company-light.png">
</picture>

## Many sites at once

For web agencies: a file with one site per line.

```bash
suveren batch sites.txt --browser
```

`reports/batch-…` gets a summary table `index.html`, `summary.csv` for Excel and a report per
site.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/batch-dark.png">
  <img alt="Summary of a list of sites" src="docs/batch-light.png">
</picture>

## In CI

```bash
suveren scan example.ru --no-open --sarif suveren.sarif --fail-on fail
```

A finding you decided to live with can be accepted in `.suveren-ignore`: the ID, the site, the
end date, the author and the reason on one line. It stays in the report but does not fail CI, and
counts again after the end date.

SARIF is read by GitHub and GitLab code scanning and DefectDojo. Exit codes, the JSON format and
plugins with your own checks are described in the [guide](docs/guide.md#ci-и-другие-инструменты)
and [docs/plugins.md](docs/plugins.md).

## Data sources

All sources are open and free, no API keys: DNS, Team Cymru (IP networks), RDAP and WHOIS, EGRUL
(Federal Tax Service), Roskomnadzor's registers of personal-data operators and of blocked
resources, Certificate Transparency logs (crt.sh, Cert Spotter), OFAC, EU and UK sanctions lists,
the retire.js database of vulnerable libraries, the address lists of AWS, Google Cloud, Oracle and
DigitalOcean.
`suveren doctor` checks that they all answer; on GitHub this runs daily.

## Limitations

- The report helps set priorities and **is not legal advice**. Every 152-FZ check names its
  article of law with a link to the text, so the conclusion can be verified.
- The home page and up to 6 inner pages are checked (`--pages`). Services present only on other
  pages may be missed.
- If a site blocks robots even in a browser, checks based on page code are "not checked" rather
  than a false "OK".
- If the site is behind a CDN, the real hosting is hidden, and Suveren says so.

## Contributing

Adding a service needs no programming: the database is a data file,
[`services.json`](src/suveren/data/services.json) — see the
[guide](docs/guide.md#как-добавить-сервис-в-базу). Or open an "Add a service" issue. Report
vulnerabilities as described in [SECURITY.md](SECURITY.md).

```bash
pip install -e ".[dev,browser]"
pytest
ruff check . && ruff format --check .
```

Tests never touch the network: registry responses and sample lists live in `tests/fixtures`.

## License

Copyright © 2026 marsilid. From version 1.1 — [GNU AGPL-3.0](LICENSE) or later: the code is
open, and any modified version, including one run as a service, must be open too. A commercial
licence is available for closed products and SaaS — see [COPYRIGHT](COPYRIGHT). Versions up to
1.0.x were published under MIT and remain under it.

Related project: [ReconLens](https://github.com/marsilid/reconlens) — passive OSINT
reconnaissance of a domain with a security grade.
