import tempfile
import unittest
from pathlib import Path

from zacaim.models import Finding, TargetSummary
from zacaim.reports import ReportBuilder


class ReportsTest(unittest.TestCase):
    def test_report_builder_writes_expected_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_dir = Path(temp_dir) / "session"
            (session_dir / "reports").mkdir(parents=True)
            summary = TargetSummary(
                target="example.com",
                target_kind="hostname",
                session_id="session_1",
                profile="standard",
                started_at="2026-03-28T10:00:00",
                output_dir=str(session_dir),
                web_observations={
                    "profile": "standard",
                    "path_hits": ["/robots.txt", "/sitemap.xml"],
                    "robots": [
                        {
                            "user_agents": ["*"],
                            "allow_count": 1,
                            "disallow_count": 2,
                            "interesting_paths": ["/admin", "/internal/debug"],
                        }
                    ],
                    "sitemaps": [
                        {
                            "kind": "urlset",
                            "url_count": 2,
                            "lastmod_count": 1,
                            "sample_urls": ["https://example.com/", "https://example.com/login"],
                            "child_sitemaps": [],
                        }
                    ],
                },
                findings=[
                    Finding(
                        title="Example finding",
                        severity="info",
                        category="web",
                        description="Example description",
                    )
                ],
            )

            output = ReportBuilder.build(summary, session_dir)
            self.assertTrue(Path(output["summary_json"]).exists())
            self.assertTrue(Path(output["findings_json"]).exists())
            self.assertTrue(Path(output["report_md"]).exists())
            report_body = Path(output["report_md"]).read_text(encoding="utf-8")
            self.assertIn("robots.txt parsed", report_body)
            self.assertIn("sitemap.xml parsed", report_body)


if __name__ == "__main__":
    unittest.main()
