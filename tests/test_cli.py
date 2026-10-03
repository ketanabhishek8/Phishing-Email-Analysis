import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from phishkit.cli import main
from tests.helpers import make_eml


def write_tmp(data: bytes) -> str:
    fd, path = tempfile.mkstemp(suffix=".eml")
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return path


class CliTests(unittest.TestCase):
    def setUp(self):
        self.clean = write_tmp(make_eml())
        self.phish = write_tmp(make_eml(
            headers={"From": "PayPal <service@paypa1.com>", "Reply-To": "x@gmail.com"},
            html='<a href="http://192.0.2.1/login">https://www.paypal.com</a>'))

    def tearDown(self):
        os.remove(self.clean)
        os.remove(self.phish)

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_json_output_is_valid(self):
        code, out, _ = self.run_cli("analyze", self.phish, "--json")
        data = json.loads(out)
        self.assertEqual(data["verdict"], "Likely phishing")
        self.assertEqual(code, 2)

    def test_text_output_and_clean_exit_code(self):
        code, out, _ = self.run_cli("analyze", self.clean, "--no-color")
        self.assertEqual(code, 0)
        self.assertIn("Verdict: Clean", out)
        self.assertNotIn("\x1b[", out)

    def test_text_output_defangs_urls(self):
        _, out, _ = self.run_cli("analyze", self.phish, "--no-color")
        self.assertIn("hxxp://192[.]0[.]2[.]1/login", out)
        self.assertNotIn("http://192.0.2.1", out)

    def test_multiple_files_json_list(self):
        code, out, _ = self.run_cli("analyze", self.clean, self.phish, "--json")
        data = json.loads(out)
        self.assertEqual(len(data), 2)
        self.assertEqual(code, 2)

    def test_missing_file_exit_3(self):
        code, _, err = self.run_cli("analyze", "/no/such/file.eml")
        self.assertEqual(code, 3)
        self.assertIn("cannot read", err.lower())


if __name__ == "__main__":
    unittest.main()
