import unittest

from phishkit import domains


class OrgDomainTests(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(domains.org_domain("mail.example.com"), "example.com")

    def test_multi_label_suffix(self):
        self.assertEqual(domains.org_domain("mail.example.co.uk"), "example.co.uk")
        self.assertEqual(domains.org_domain("a.b.shop.com.au"), "shop.com.au")

    def test_bare_domain_and_case(self):
        self.assertEqual(domains.org_domain("Example.COM."), "example.com")


class DomainOfTests(unittest.TestCase):
    def test_extracts_from_address_forms(self):
        self.assertEqual(domains.domain_of("Alice <alice@Mail.Example.com>"), "mail.example.com")
        self.assertEqual(domains.domain_of("bob@example.org"), "example.org")
        self.assertEqual(domains.domain_of("<bounce@x.net>"), "x.net")
        self.assertEqual(domains.domain_of("no address here"), "")


class LookalikeTests(unittest.TestCase):
    def test_digit_swap(self):
        self.assertEqual(domains.lookalike_of("paypa1.com"), "paypal.com")

    def test_rn_for_m(self):
        self.assertEqual(domains.lookalike_of("rnicrosoft.com"), "microsoft.com")

    def test_edit_distance(self):
        self.assertEqual(domains.lookalike_of("arnazon.com"), "amazon.com")
        self.assertEqual(domains.lookalike_of("micros0ft-support.com"), "microsoft.com")

    def test_brand_embedded_in_longer_domain(self):
        self.assertEqual(domains.lookalike_of("paypal-secure-login.com"), "paypal.com")

    def test_real_brand_domains_are_not_lookalikes(self):
        self.assertIsNone(domains.lookalike_of("paypal.com"))
        self.assertIsNone(domains.lookalike_of("mail.paypal.com"))
        self.assertIsNone(domains.lookalike_of("login.microsoftonline.com"))

    def test_unrelated_domain(self):
        self.assertIsNone(domains.lookalike_of("example.org"))

    def test_punycode_homoglyph(self):
        # "раypal.com" with Cyrillic р and а
        self.assertEqual(domains.lookalike_of("xn--ypal-43d9g.com"), "paypal.com")


class IdnTests(unittest.TestCase):
    def test_punycode_detect_and_decode(self):
        self.assertTrue(domains.is_punycode("xn--ypal-43d9g.com"))
        self.assertFalse(domains.is_punycode("paypal.com"))
        self.assertEqual(domains.decode_idn("xn--ypal-43d9g.com"), "раypal.com")


class BrandInTests(unittest.TestCase):
    def test_brand_in_text(self):
        self.assertEqual(domains.brand_in("PayPal Customer Service"), "paypal")
        self.assertEqual(domains.brand_in("Microsoft 365 Team"), "microsoft")
        self.assertIsNone(domains.brand_in("Bob from accounting"))


if __name__ == "__main__":
    unittest.main()
