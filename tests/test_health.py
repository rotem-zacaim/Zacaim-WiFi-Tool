import unittest

from zacaim.health import ToolInstaller


class HealthTest(unittest.TestCase):
    def test_assess_missing_splits_supported_and_manual_tools(self) -> None:
        payload = {
            "tools": {
                "nmap": "",
                "curl": "/usr/bin/curl",
                "httpx": "",
                "katana": "",
                "dig": "",
                "ssh-keyscan": "",
            }
        }

        plan = ToolInstaller.assess_missing(payload)

        self.assertIn("nmap", plan["supported_tools"])
        self.assertIn("dig", plan["supported_tools"])
        self.assertIn("ssh-keyscan", plan["supported_tools"])
        self.assertIn("httpx", plan["unsupported_tools"])
        self.assertIn("katana", plan["unsupported_tools"])
        self.assertIn("nmap", plan["packages"])
        self.assertIn("dnsutils", plan["packages"])
        self.assertIn("openssh-client", plan["packages"])


if __name__ == "__main__":
    unittest.main()
