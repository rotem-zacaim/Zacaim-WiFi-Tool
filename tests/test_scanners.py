import unittest

from zacaim.scanners import TargetScanner, WebScanner


class ScannersTest(unittest.TestCase):
    def test_standard_web_plan_contains_twenty_or_more_modules(self) -> None:
        plan = WebScanner.build_progress_plan("https://example.com", "standard")
        self.assertGreaterEqual(len(plan), 20)

    def test_standard_web_plan_includes_new_recon_modules(self) -> None:
        ids = {step["id"] for step in WebScanner.build_progress_plan("https://example.com", "standard")}
        self.assertTrue({"dnsx", "naabu", "ffuf", "nikto", "gau", "katana"}.issubset(ids))

    def test_standard_host_plan_includes_expanded_modules(self) -> None:
        ids = {step["id"] for step in TargetScanner.build_progress_plan("example.com", "standard")}
        self.assertTrue({"nmap", "naabu", "dnsx", "sslscan", "enum4linux", "ldapsearch", "rdpscan", "web_enrich"}.issubset(ids))


if __name__ == "__main__":
    unittest.main()
