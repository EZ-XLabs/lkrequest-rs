# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in `lkrequest`, please report it
**privately**. Do **not** open a public GitHub issue, pull request, or
discussion for security-sensitive matters, as that may expose other users to
risk before a fix is available.

- **Contact:** email `art_liberoxr@mail.com` with the subject line prefixed
  `[lkrequest security]`.
- **Include (where possible):** affected crate(s) and version/commit, a
  description of the issue and its impact, reproduction steps or a
  proof-of-concept, and any suggested remediation.

### What to expect

- **Acknowledgement:** we aim to acknowledge your report within **72 hours**.
- **Triage & updates:** after acknowledgement we will work to confirm the
  issue, assess severity and impact, and keep you informed of progress.
- **Coordinated disclosure:** we follow a coordinated-disclosure model. We ask
  that you give us a reasonable window to develop and ship a fix before any
  public disclosure, and we will credit reporters who wish to be named once a
  fix is released. Please do not disclose the issue publicly until we have
  agreed on a disclosure timeline.

This project is pre-1.0 research software. Response times are best-effort and
are not backed by a contractual SLA.

## Supported Versions

| Version | Supported                          |
| ------- | ---------------------------------- |
| 0.1.x   | Pre-release / best-effort only     |
| < 0.1   | Not supported                      |

`lkrequest` has not yet reached a stable 1.0 release. The `0.1.x` line is
pre-release software; security fixes are provided on a best-effort basis and
typically land in the latest commit rather than as backported point releases.
There are no guarantees of long-term support for any version prior to a stable
release. Always track the latest published version for the most current fixes.

## Intended Use / Responsible Use

`lkrequest` provides byte-level control over TLS, HTTP/2, and HTTP/3/QUIC wire
formats in order to emulate real browser network fingerprints. This capability
is powerful and is intended for **legitimate, authorized use only**.

**Intended uses include:**

- Authorized security testing and red-team engagements where you have explicit
  permission to test the target.
- Anti-bot, fingerprinting, and browser-emulation **research**.
- Web scraping and automation of sites that **you own** or that you are
  **explicitly authorized** to access, in compliance with their terms.
- Building and validating browser-fidelity / fingerprint-consistency tooling.
- Privacy and network-protocol research and education.

**You must NOT use `lkrequest` to:**

- Bypass authentication, authorization, or other access controls on systems you
  do not own or are not authorized to access.
- Violate a site's Terms of Service, robots directives, rate limits, or
  applicable laws and regulations (including computer-misuse, anti-fraud, and
  data-protection law).
- Evade or defeat fraud-prevention, abuse-prevention, or security controls in
  order to commit fraud, abuse, or other unlawful activity.
- Conduct credential stuffing, denial-of-service, spam, scalping, ad fraud, or
  any other abusive or malicious activity.
- Misrepresent your identity or affiliation in a manner that is deceptive or
  unlawful.

You are solely responsible for ensuring that your use of this software is
lawful and authorized in your jurisdiction and for the systems you interact
with. The maintainers and contributors provide this software **as is**, for
research and legitimate engineering purposes, and accept no responsibility for
misuse. See `LICENSE.txt` (Apache-2.0) for the full warranty
disclaimer and limitation of liability.
