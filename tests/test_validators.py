import unittest

from zacaim.validators import TargetValidator, normalize_url, slugify


class ValidatorsTest(unittest.TestCase):
    def test_normalize_url_adds_https_by_default(self) -> None:
        payload = normalize_url("example.com")
        self.assertEqual(payload["url"], "https://example.com/")
        self.assertEqual(payload["scheme"], "https")
        self.assertEqual(payload["port"], 443)

    def test_target_validator_accepts_ip_and_hostname(self) -> None:
        self.assertEqual(TargetValidator.normalize("127.0.0.1"), "127.0.0.1")
        self.assertEqual(TargetValidator.normalize("example.internal"), "example.internal")

    def test_slugify_replaces_invalid_characters(self) -> None:
        self.assertEqual(slugify("My Target / Prod"), "My_Target_Prod")


if __name__ == "__main__":
    unittest.main()
