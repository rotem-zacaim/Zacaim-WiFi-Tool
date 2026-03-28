import unittest

from zacaim.parsers import parse_robots_txt, parse_security_txt, parse_sitemap_xml


class ParsersTest(unittest.TestCase):
    def test_parse_robots_txt_extracts_directives(self) -> None:
        content = """
        User-agent: *
        Disallow: /admin
        Disallow: /internal/debug
        Allow: /public
        Sitemap: https://example.com/sitemap.xml
        """.strip()

        parsed = parse_robots_txt(content, source_url="https://example.com/robots.txt")

        self.assertEqual(parsed["group_count"], 1)
        self.assertEqual(parsed["disallow_count"], 2)
        self.assertEqual(parsed["allow_count"], 1)
        self.assertIn("*", parsed["user_agents"])
        self.assertIn("/admin", parsed["interesting_paths"])
        self.assertIn("https://example.com/admin", parsed["interesting_urls"])
        self.assertIn("https://example.com/sitemap.xml", parsed["sitemaps"])

    def test_parse_sitemap_xml_extracts_urls(self) -> None:
        content = """
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
          <url>
            <loc>https://example.com/</loc>
            <lastmod>2026-03-28</lastmod>
          </url>
          <url>
            <loc>https://example.com/login</loc>
          </url>
        </urlset>
        """.strip()

        parsed = parse_sitemap_xml(content, source_url="https://example.com/sitemap.xml")

        self.assertEqual(parsed["kind"], "urlset")
        self.assertEqual(parsed["url_count"], 2)
        self.assertEqual(parsed["lastmod_count"], 1)
        self.assertIn("https://example.com/login", parsed["sample_urls"])

    def test_parse_sitemap_index_extracts_child_sitemaps(self) -> None:
        content = """
        <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
          <sitemap>
            <loc>https://example.com/sitemap-pages.xml</loc>
          </sitemap>
          <sitemap>
            <loc>https://example.com/sitemap-blog.xml</loc>
            <lastmod>2026-03-28</lastmod>
          </sitemap>
        </sitemapindex>
        """.strip()

        parsed = parse_sitemap_xml(content, source_url="https://example.com/sitemap.xml")

        self.assertEqual(parsed["kind"], "sitemapindex")
        self.assertEqual(parsed["url_count"], 2)
        self.assertEqual(parsed["lastmod_count"], 1)
        self.assertIn("https://example.com/sitemap-pages.xml", parsed["child_sitemaps"])

    def test_parse_security_txt_extracts_contacts(self) -> None:
        content = """
        Contact: mailto:security@example.com
        Contact: https://example.com/security
        Policy: https://example.com/policy
        Encryption: https://example.com/pgp.txt
        """.strip()

        parsed = parse_security_txt(content, source_url="https://example.com/.well-known/security.txt")

        self.assertEqual(parsed["field_count"], 3)
        self.assertEqual(parsed["contact_count"], 2)
        self.assertIn("mailto:security@example.com", parsed["contacts"])


if __name__ == "__main__":
    unittest.main()
