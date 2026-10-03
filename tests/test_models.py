import json
import unittest

from phishkit.models import Finding, Report, Severity


class FindingTests(unittest.TestCase):
    def test_to_dict_uses_severity_label(self):
        f = Finding("urls", Severity.HIGH, "IP address in URL", "detail", "hxxp://1[.]2[.]3[.]4")
        d = f.to_dict()
        self.assertEqual(d["severity"], "high")
        self.assertEqual(d["weight"], 30)
        self.assertEqual(d["title"], "IP address in URL")

    def test_severity_weights(self):
        self.assertEqual(
            [s.value for s in Severity], [0, 5, 15, 30, 50]
        )


class ReportTests(unittest.TestCase):
    def test_report_is_json_serialisable(self):
        r = Report(
            summary={"subject": "hi"},
            findings=[Finding("auth", Severity.MEDIUM, "SPF softfail")],
            score=15,
            verdict="Clean",
        )
        data = json.loads(json.dumps(r.to_dict()))
        self.assertEqual(data["findings"][0]["severity"], "medium")
        self.assertEqual(data["score"], 15)
        self.assertEqual(data["urls"], [])


if __name__ == "__main__":
    unittest.main()
