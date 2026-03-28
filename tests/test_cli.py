import unittest

from zacaim.app import parse_args


class CliTest(unittest.TestCase):
    def test_engagement_requires_subcommand(self) -> None:
        with self.assertRaises(SystemExit):
            parse_args(["engagement"])

    def test_web_scan_parses_profile(self) -> None:
        args = parse_args(["web", "scan", "https://example.com", "--profile", "deep"])
        self.assertEqual(args.command, "web")
        self.assertEqual(args.web_command, "scan")
        self.assertEqual(args.profile, "deep")


if __name__ == "__main__":
    unittest.main()
