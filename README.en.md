<div align="center">

# Suveren

**How much does your website depend on foreign services, and what breaks if they cut you off?**

[![CI](https://github.com/marsilid/suveren/actions/workflows/ci.yml/badge.svg)](https://github.com/marsilid/suveren/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%E2%80%933.14-blue)
![License](https://img.shields.io/badge/license-MIT-green)

[Русская версия](README.md)

</div>

Suveren inspects a domain and finds everything that runs on infrastructure outside Russia:
DNS, mail, hosting, CDN, registrar, TLS certificate, and the scripts and widgets on the page.
For each dependency it explains the risk, suggests a Russian alternative, and grades the
domain's independence from **A** to **F**.

The tool is aimed at Russian businesses, web agencies and data-protection officers, so its
interface and reports are in Russian.

![Terminal output](docs/demo.svg)

## What it checks

| Layer | Detected from |
|---|---|
| DNS servers | NS records and the network (ASN) of their IPs |
| Mail | MX records |
| Hosting | website IP → ASN and the owner's country |
| CDN / anti-DDoS | website IP |
| Registrar | RDAP / WHOIS |
| Domain zone | TLD |
| TLS certificate | TLS handshake |
| Scripts and widgets | home page HTML: analytics, captcha, fonts, chats, maps, video, payments, social sign-in |

The database has **150+ services**, both foreign and Russian; run `suveren services` to list it.
A service's country is the jurisdiction of the company that runs it, since sanctions apply to
companies, not data centres.

## Install and run

```bash
pip install git+https://github.com/marsilid/suveren.git
suveren scan example.ru
suveren scan example.ru --json before.json
suveren diff before.json after.json
```

On Windows you can also run `Suveren.bat`, which installs everything on first launch.

![HTML report](docs/report-screenshot.png)

## Scoring

Each category with a foreign dependency yields one finding: high −20, medium −10, low −4.
Grades: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, otherwise F. When a category has both foreign and
Russian servers (e.g. a secondary NS in Russia), the risk is lowered one step.

## Limitations

Only the home page is scanned for scripts; a site behind a CDN hides its real hosting. The scan
is passive: public DNS, WHOIS, one TLS handshake and one page load. The report is a triage aid,
not legal advice.

## Contributing

Services live in [`src/suveren/services.py`](src/suveren/services.py): add a `Service(...)`
entry, add a test to `tests/test_services.py`, and open a pull request.

## License

[MIT](LICENSE)
