# How organisations defend against phishing

No single control stops phishing. Mature organisations layer defences so that an email that
slips past one layer is caught by the next, and so that a user who does click causes as
little damage as possible. This document walks through those layers, maps them to the
techniques in PhishKit's samples, and ends with a triage playbook.

---

## 1. Stop your domain being spoofed: SPF, DKIM and DMARC

These standards protect **your** domain from being used in phishing against your customers,
partners and staff. Sample 02 (a spoof of `paypal.com`) is what they are designed to stop.

| Standard | What it proves | Published as |
|---|---|---|
| **SPF** (RFC 7208) | The sending server's IP is authorised by the *envelope* (Return-Path) domain | TXT at the domain: `v=spf1 include:_spf.google.com -all` |
| **DKIM** (RFC 6376) | The message was signed by the domain in `d=` and not altered in transit | Public key at `selector._domainkey.domain` |
| **DMARC** (RFC 7489) | SPF or DKIM passed **for a domain aligned with the visible From address**, plus what receivers should do if not | TXT at `_dmarc.domain`: `v=DMARC1; p=reject; rua=mailto:…` |

SPF and DKIM alone do not protect the From address the user sees. Sample 01 passes SPF for
the attacker's own bulk-mail domain. **Alignment** in DMARC is what ties authentication to the
visible sender.

**Rolling out DMARC safely**

1. Inventory every service that sends as your domain: the mail platform, CRM, marketing,
   ticketing, HR and invoicing systems.
2. Publish `p=none` with `rua=` aggregate reporting, and read the reports for a few weeks.
   Fix SPF includes and enable DKIM signing for each legitimate sender.
3. Move to `p=quarantine`, optionally with `pct=` to ramp up gradually.
4. Move to `p=reject`. Set `sp=reject` for subdomains.
5. Protect parked and non-sending domains with `v=spf1 -all` and `v=DMARC1; p=reject`.
   Attackers love domains that send no mail but have no policy.

Related standards include **ARC**, which preserves authentication results across forwarders
and mailing lists, **MTA-STS / TLS-RPT**, which enforce TLS between mail servers, and **BIMI**,
which shows a verified logo once you are at `p=quarantine` or `p=reject`.

**On the receiving side**, make sure the gateway actually *enforces* the sender's DMARC policy
and that allow-list rules do not override it. A `dmarc=fail` against `p=reject` that still
reaches an inbox, like sample 02, is a configuration finding in its own right.

## 2. Filter what comes in

DMARC cannot help with lookalike domains (samples 01 and 05), compromised supplier accounts
(sample 03) or free webmail (sample 04). Those need content and context filtering.

- **Secure email gateway or cloud email security** (Microsoft Defender for Office 365,
  Proofpoint, Mimecast, Google Workspace and similar) applies sender reputation, anti-spoofing
  and impersonation models.
- **Attachment controls**
  - Block executable and script types outright (`.exe .scr .js .vbs .hta .lnk .iso .img .one`…),
    including inside archives.
  - Detonate other attachments in a sandbox before delivery. Treat password-protected archives
    as suspicious, because they cannot be scanned.
  - Block or sandbox **HTML attachments** from external senders. This defeats HTML smuggling
    (sample 05) and local credential-harvesting pages.
- **Macros:** block VBA macros in files from the internet (Microsoft's default since 2022,
  and enforceable by policy), and preserve **Mark-of-the-Web** so that protection still works
  (sample 03).
- **URL protection:** rewrite links for **time-of-click** checking, because phishing pages are
  often clean at delivery and turned malicious hours later. Block newly registered domains,
  free-hosting and tunnelling platforms where the business does not need them, and known
  shorteners.
- **Impersonation protection:**
  - Watch for display names matching executives, plus lookalike versions of your own and your
    suppliers' domains.
  - Tag external email with a banner, and flag Reply-To addresses that differ from From
    (samples 03 and 04).
- **Lookalike-domain monitoring:** watch certificate-transparency logs and new registrations
  for typo and homoglyph variants of your brands, and request takedowns.

## 3. Assume someone will click: identity and endpoint

- **Phishing-resistant MFA.** Adversary-in-the-middle kits relay one-time codes and push
  approvals in real time, so SMS and app codes are no longer enough for high-value accounts.
  FIDO2 security keys and passkeys are bound to the real domain and cannot be phished.
- **Conditional access:** require compliant devices, block legacy authentication, and alert on
  impossible travel and unfamiliar sign-in properties. Shorten session lifetimes and use token
  protection so stolen cookies are less useful.
- **Endpoint protection:** EDR, plus attack-surface-reduction rules (for example, block Office
  from creating child processes and block executable content from email or webmail), and
  application control. Consider preventing users from mounting ISO and VHD files.
- **Least privilege:** a phished account without admin rights or broad mailbox access limits
  the blast radius.

## 4. People and process

- **Awareness training and simulations**, measured on the *report rate* and *time to report*,
  not just the click rate. A workforce that reports quickly is a sensor network.
- **A one-click "Report phishing" button** that sends the original `.eml` (with headers) to the
  SOC. That file is exactly what PhishKit analyses.
- **Payment controls for BEC** (samples 03 and 04): verify any change of bank details or urgent
  payment request by calling a known phone number, not one from the email, and require
  dual approval above a threshold. This process stops BEC even when every technical control
  passes.
- **Supplier security:** include email security requirements (MFA, DMARC) in supplier
  agreements. Compromised supplier mailboxes are a leading source of invoice fraud.

## 5. Detect and respond: a triage playbook

When a user reports an email, or a gateway alert fires:

1. **Collect** the original `.eml` with full headers. Forwarded copies lose the evidence.
2. **Triage** with PhishKit (`python -m phishkit analyze report.eml --live`), and read the
   findings in this order:
   - **Authentication:** did the receiving server record SPF, DKIM and DMARC passes? Does
     DMARC alignment hold?
   - **Identity:** do From, Reply-To and Return-Path agree? Is the domain a lookalike?
   - **Links:** where do they really go? Check the domains' age and reputation.
   - **Attachments:** submit hashes to threat intel (`--vt`) and detonate unknowns in a sandbox.
     Never open them on a workstation.
3. **Scope.** Search all mailboxes for the same sender, subject, URL domains and attachment
   hashes, and check proxy and DNS logs for anyone who visited the URLs.
4. **Contain.** Purge the messages from every mailbox, and block the sender, domains, URLs and
   hashes at the gateway, proxy, DNS filter and EDR.
5. **Eradicate.** For users who entered credentials:
   - Reset the password and revoke sessions and refresh tokens.
   - Review MFA methods and OAuth app consents for anything the attacker added.
   - Look for new **inbox rules** that forward or hide mail, a common post-compromise step.
6. **Recover and learn.** Notify affected users and any impersonated supplier, share
   indicators (for example via MISP or an ISAC), request takedowns, and tune detections for
   whatever got through.

## Mapping to MITRE ATT&CK

| Technique | ID | Where it appears | Key controls |
|---|---|---|---|
| Phishing: spearphishing attachment | T1566.001 | Samples 03, 05 | Attachment blocking, sandboxing, macro policy |
| Phishing: spearphishing link | T1566.002 | Samples 01, 02 | Time-of-click URL protection, phishing-resistant MFA |
| Impersonation | T1656 | Samples 02, 04, corpus "Microsoft account" campaign | DMARC enforcement, impersonation protection, payment verification |
| Acquire infrastructure: domains | T1583.001 | Lookalike domains in samples 01, 05 | Lookalike monitoring, newly registered domain blocking |
| HTML smuggling | T1027.006 | Sample 05 | Block or sandbox HTML attachments |
| Mark-of-the-Web bypass | T1553.005 | ISO payload in sample 05 | Block ISO/IMG, ASR rules |
| User execution: malicious file / link | T1204.002 / T1204.001 | Samples 03, 05 / 01, 02 | Training, EDR, ASR rules |
| Email hiding rules (post-compromise) | T1564.008 | After credential theft | Audit inbox rules during response |

## Where PhishKit fits

PhishKit automates step 2 of the playbook. It turns a reported `.eml` into an explained,
scored report in seconds, so analysts spend their time on scoping and response rather than
reading raw headers. It is a triage aid, not a gateway. As the
[sample analyses](sample-analyses.md) show, a well-crafted email with clean authentication and
no technical tells can still score low, which is why the layers above exist.
