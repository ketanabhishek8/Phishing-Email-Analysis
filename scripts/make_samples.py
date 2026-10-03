"""Generate the sample emails in samples/.

Every sample is modelled on a real phishing technique but is completely inert:
- attacker infrastructure uses reserved domains (.test / .example, RFC 2606) and
  documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, RFC 5737);
- "malicious" attachments are harmless stand-ins that only *look* dangerous to the
  analyser (a dummy vbaProject.bin, a script that decodes a plain sentence).

Output is deterministic (fixed MIME boundaries and zip timestamps) so the hashes
quoted in docs/sample-analyses.md stay stable.

Usage: python scripts/make_samples.py
"""

from __future__ import annotations

import base64
import io
import zipfile
from email.message import EmailMessage
from email.policy import SMTP
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "samples"
ZIP_TIME = (2026, 9, 21, 9, 0, 0)


def build(top_headers: list[tuple[str, str]], headers: dict, text: str, html: str | None = None,
          attachments=(), name: str = "") -> bytes:
    msg = EmailMessage()
    for key, value in headers.items():
        msg[key] = value
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    for filename, payload, maintype, subtype in attachments:
        msg.add_attachment(payload, maintype=maintype, subtype=subtype, filename=filename)
    # Fixed boundaries keep the output byte-for-byte reproducible.
    for i, part in enumerate(p for p in msg.walk() if p.is_multipart()):
        part.set_boundary(f"=_phishkit_{name}_{i}")
    body = msg.as_bytes(policy=SMTP)
    # Receiving servers prepend trace headers, newest on top.
    trace = "".join(f"{k}: {v}\r\n" for k, v in top_headers).encode()
    return trace + body


def ooxml_with_macro() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in (
            ("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>'),
            ("word/document.xml", '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Invoice INV-20931. Enable editing and content to view.</w:t></w:r></w:p></w:body></w:document>'),
            ("word/vbaProject.bin", "PhishKit inert test stand-in for a VBA project. Contains no code."),
        ):
            zf.writestr(zipfile.ZipInfo(name, date_time=ZIP_TIME), data)
    return buf.getvalue()


def smuggling_html() -> bytes:
    harmless = base64.b64encode(b"This is a harmless PhishKit test file. No malware here.").decode()
    return f"""<!DOCTYPE html>
<html><head><title>Remittance Advice</title></head>
<body style="font-family:Arial">
<p>Loading your secure document, please wait...</p>
<script>
  // Technique demo only: decodes a harmless sentence and offers it as a download.
  var data = atob("{harmless}");
  var bytes = new Uint8Array(data.length);
  for (var i = 0; i < data.length; i++) bytes[i] = data.charCodeAt(i);
  var blob = new Blob([bytes], {{type: "application/octet-stream"}});
  var a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "Remittance_0923.iso";
  a.click();
</script>
</body></html>
""".encode()


def samples() -> dict[str, bytes]:
    out = {}

    out["01-m365-credential-harvest.eml"] = build(
        [
            ("Received", "from mx01.contoso-corp.example (mx01.contoso-corp.example [10.20.0.11]) by mbx03.contoso-corp.example with ESMTPS; Mon, 21 Sep 2026 08:14:09 +0000"),
            ("Authentication-Results", "mx01.contoso-corp.example; spf=pass (sender IP is 203.0.113.45) smtp.mailfrom=mailer-srv.test; dkim=none (message not signed); dmarc=none action=none header.from=micros0ft-365-auth.test"),
            ("Received-SPF", "Pass (mx01.contoso-corp.example: domain of mailer-srv.test designates 203.0.113.45 as permitted sender) client-ip=203.0.113.45;"),
            ("Received", "from vps-88213.mailer-srv.test (vps-88213.mailer-srv.test [203.0.113.45]) by mx01.contoso-corp.example with ESMTP; Mon, 21 Sep 2026 08:14:07 +0000"),
        ],
        {
            "From": '"Microsoft 365 Security" <no-reply@micros0ft-365-auth.test>',
            "To": "j.smith@contoso-corp.example",
            "Subject": "Action required: your password expires in 24 hours",
            "Date": "Mon, 21 Sep 2026 08:14:02 +0000",
            "Message-ID": "<20260921081402.88213@vps-88213.mailer-srv.test>",
            "Return-Path": "<bounce-7731@mailer-srv.test>",
            "X-Mailer": "PHPMailer 6.8.0",
        },
        "Microsoft 365\n\nThe password for j.smith@contoso-corp.example expires in 24 hours.\n"
        "Keep your current password: https://login.microsoftonline.com/reset\n\nMicrosoft Security Team",
        """<html><body style="font-family:Segoe UI,Arial">
<p><b>Microsoft 365</b></p>
<p>The password for <b>j.smith@contoso-corp.example</b> expires in <b>24 hours</b>.</p>
<p>To keep your current password, verify your account below.</p>
<p><a href="https://m365-reset-7731.web.app/login?u=j.smith@contoso-corp.example">https://login.microsoftonline.com/reset</a></p>
<p style="color:#888;font-size:11px">Microsoft Corporation, One Microsoft Way, Redmond, WA</p>
<img src="https://m365-reset-7731.web.app/t.gif?id=88213" width="1" height="1">
</body></html>""",
        name="01",
    )

    out["02-paypal-spoof-punycode.eml"] = build(
        [
            ("Authentication-Results", "mx.mail-provider.example; spf=fail (mx.mail-provider.example: domain of root@vps-2231.test does not designate 198.51.100.23 as permitted sender) smtp.mailfrom=root@vps-2231.test; dkim=none; dmarc=fail (p=REJECT sp=REJECT dis=QUARANTINE) header.from=paypal.com"),
            ("Received", "from vps-2231.test (vps-2231.test [198.51.100.23]) by mx.mail-provider.example with ESMTP id 4f2a; Tue, 22 Sep 2026 17:41:55 +0000"),
        ],
        {
            "From": '"PayPal" <service@paypal.com>',
            "To": "customer@mail-provider.example",
            "Subject": "Your account has been limited - confirm your information",
            "Date": "Tue, 22 Sep 2026 17:41:50 +0000",
            "Message-ID": "<1726000915.2231@vps-2231.test>",
            "Return-Path": "<root@vps-2231.test>",
        },
        "We noticed unusual activity. Your PayPal account has been limited.\n"
        "Confirm your information within 48 hours: https://bit.ly/3pPaYpL-verify\n",
        """<html><body style="font-family:Helvetica,Arial">
<h2 style="color:#003087">PayPal</h2>
<p>Dear Customer,</p>
<p>We noticed unusual activity and have <b>limited your account</b>. Confirm your information within 48 hours to restore access.</p>
<p><a href="https://xn--ypal-43d9g.test/signin?session=9a7e">Confirm your information</a></p>
<p>Or sign in at <a href="http://198.51.100.23/paypal/webscr?cmd=_login-run">www.paypal.com</a></p>
<p>Resolution centre: <a href="https://paypal.com.account-verify.test/resolution">https://paypal.com/resolution</a></p>
<p>Shortcut: https://bit.ly/3pPaYpL-verify</p>
</body></html>""",
        name="02",
    )

    out["03-invoice-macro-attachment.eml"] = build(
        [
            ("Authentication-Results", "mx.fabrikam.example; spf=pass smtp.mailfrom=northwind-traders.test; dkim=pass header.d=northwind-traders.test header.s=sel1 header.b=Qm9ndXM; dmarc=pass action=none header.from=northwind-traders.test"),
            ("Received", "from mail.northwind-traders.test (mail.northwind-traders.test [192.0.2.80]) by mx.fabrikam.example with ESMTPS; Wed, 23 Sep 2026 11:02:31 +0000"),
        ],
        {
            "From": '"Accounts Receivable" <ar@northwind-traders.test>',
            "Reply-To": "phishkit-sample-ar-payments@outlook.com",
            "To": "ap@fabrikam.example",
            "Subject": "RE: Overdue invoice INV-20931 - final notice",
            "Date": "Wed, 23 Sep 2026 11:02:25 +0000",
            "Message-ID": "<a81c2f9e-20931@mail.northwind-traders.test>",
            "Return-Path": "<ar@northwind-traders.test>",
        },
        "Hello,\n\nPlease find attached the overdue invoice INV-20931. Our bank details have changed; "
        "the new details are in the document.\nYou may need to click 'Enable Editing' and "
        "'Enable Content' to view it correctly.\n\nPlease process payment today to avoid late fees.\n\n"
        "Regards,\nAccounts Receivable\nNorthwind Traders",
        attachments=[("Invoice_INV-20931.docm", ooxml_with_macro(), "application",
                      "vnd.ms-word.document.macroEnabled.12")],
        name="03",
    )

    out["04-bec-ceo-fraud.eml"] = build(
        [
            ("Authentication-Results", "mx.contoso-corp.example; spf=pass smtp.mailfrom=gmail.com; dkim=pass header.d=gmail.com header.s=20230601; dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com"),
            ("Received", "from mail-sor-f41.google.com (mail-sor-f41.google.com [198.51.100.141]) by mx.contoso-corp.example with ESMTPS; Thu, 24 Sep 2026 06:55:12 +0000"),
        ],
        {
            "From": '"James Carter (CEO) jcarter@contoso-corp.example" <phishkit-sample-ceo-office@gmail.com>',
            "Reply-To": "phishkit-sample-exec@outlook.com",
            "To": "finance.team@contoso-corp.example",
            "Subject": "Urgent - confidential request",
            "Date": "Thu, 24 Sep 2026 06:55:08 +0000",
            "Message-ID": "<CAJx7K2pQ8f1-ceo@mail.gmail.com>",
        },
        "Hi,\n\nAre you at your desk? I need you to process an urgent wire transfer for an "
        "acquisition we are closing today. It is confidential, so please do not discuss it with "
        "anyone else in the office.\n\nI'm in meetings all day and can only be reached by email. "
        "Reply and I will send the beneficiary details.\n\nJames Carter\nChief Executive Officer\n"
        "Sent from my iPhone",
        name="04",
    )

    out["05-html-smuggling.eml"] = build(
        [
            ("Authentication-Results", "mx.fabrikam.example; spf=pass smtp.mailfrom=docusign-notify.test; dkim=pass header.d=docusign-notify.test header.s=k1 header.b=Ym9ndXM; dmarc=pass action=none header.from=docusign-notify.test"),
            ("Received", "from smtp.docusign-notify.test (smtp.docusign-notify.test [203.0.113.200]) by mx.fabrikam.example with ESMTPS; Fri, 25 Sep 2026 14:20:44 +0000"),
        ],
        {
            "From": '"DocuSign" <dse@docusign-notify.test>',
            "To": "payables@fabrikam.example",
            "Subject": "Completed: Remittance Advice 0923 - please review",
            "Date": "Fri, 25 Sep 2026 14:20:40 +0000",
            "Message-ID": "<0923.remit@smtp.docusign-notify.test>",
            "Return-Path": "<bounce@docusign-notify.test>",
        },
        "Your document has been completed.\nOpen the attached remittance advice to review and "
        "download your copy.\n\nDocuSign Electronic Signature Service",
        """<html><body style="font-family:Arial">
<div style="background:#1e1e5c;color:#fff;padding:16px"><b>DocuSign</b></div>
<p>Your document has been completed.</p>
<p>Open the attached <b>Remittance_Advice_0923.html</b> to review and download your copy.</p>
</body></html>""",
        attachments=[("Remittance_Advice_0923.html", smuggling_html(), "text", "html")],
        name="05",
    )

    out["06-legit-newsletter.eml"] = build(
        [
            ("Authentication-Results", "mx.mail-provider.example; spf=pass smtp.mailfrom=bounces.example.com; dkim=pass header.d=example.com header.s=news2026 header.b=TGVnaXQ; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com"),
            ("Received", "from out-12.mail.example.com (out-12.mail.example.com [192.0.2.12]) by mx.mail-provider.example with ESMTPS; Sat, 26 Sep 2026 07:00:03 +0000"),
        ],
        {
            "From": '"The Example Weekly" <news@example.com>',
            "To": "reader@mail-provider.example",
            "Subject": "This week: five tips for safer passwords",
            "Date": "Sat, 26 Sep 2026 07:00:00 +0000",
            "Message-ID": "<weekly-2026-39@news.example.com>",
            "Return-Path": "<bounce-reader@bounces.example.com>",
            "List-Unsubscribe": "<https://www.example.com/unsubscribe?u=4821>, <mailto:unsubscribe@example.com>",
            "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
        },
        "The Example Weekly - issue 39\n\nFive tips for safer passwords: https://www.example.com/blog/password-tips\n\n"
        "Unsubscribe: https://www.example.com/unsubscribe?u=4821\n",
        """<html><body style="font-family:Georgia,serif">
<h1>The Example Weekly</h1>
<p>Issue 39 &middot; Five tips for safer passwords</p>
<p>Password managers, passphrases and multi-factor authentication make the biggest difference.
<a href="https://www.example.com/blog/password-tips">Read the article</a>.</p>
<p style="font-size:12px;color:#777">You are receiving this because you subscribed at example.com.
<a href="https://www.example.com/unsubscribe?u=4821">Unsubscribe</a></p>
</body></html>""",
        name="06",
    )
    return out


def main():
    OUT.mkdir(exist_ok=True)
    for name, data in samples().items():
        (OUT / name).write_bytes(data)
        print(f"wrote samples/{name} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
