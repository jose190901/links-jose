from html.parser import HTMLParser
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
HTML_PATH = ROOT / "index.html"
CSS_PATH = ROOT / "static" / "style.css"


class SiteParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.elements = []

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))


class SiteSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = HTML_PATH.read_text(encoding="utf-8")
        cls.css = CSS_PATH.read_text(encoding="utf-8")
        cls.parser = SiteParser()
        cls.parser.feed(cls.html)

    def test_security_policy_blocks_unneeded_capabilities(self):
        policies = [
            attrs.get("content", "")
            for tag, attrs in self.parser.elements
            if tag == "meta"
            and attrs.get("http-equiv", "").lower() == "content-security-policy"
        ]
        self.assertEqual(len(policies), 1)
        policy = policies[0]
        for directive in (
            "default-src 'self'",
            "script-src 'none'",
            "object-src 'none'",
            "base-uri 'none'",
            "form-action 'none'",
        ):
            self.assertIn(directive, policy)
        self.assertNotIn("'unsafe-inline'", policy)
        self.assertNotIn("'unsafe-eval'", policy)

    def test_page_does_not_load_third_party_assets(self):
        asset_urls = []
        for tag, attrs in self.parser.elements:
            if tag in {"img", "script", "link"}:
                asset_urls.extend(
                    value
                    for key in ("src", "href")
                    if (value := attrs.get(key))
                )
        self.assertTrue(asset_urls)
        self.assertTrue(all(not url.startswith(("http://", "https://")) for url in asset_urls))

    def test_external_links_are_https_and_isolated(self):
        links = [attrs for tag, attrs in self.parser.elements if tag == "a"]
        self.assertGreaterEqual(len(links), 4)
        for attrs in links:
            self.assertTrue(attrs.get("href", "").startswith("https://"))
            self.assertEqual(attrs.get("target"), "_blank")
            rel = set(attrs.get("rel", "").split())
            self.assertTrue({"noopener", "noreferrer"}.issubset(rel))

    def test_html_has_no_inline_style_or_event_handlers(self):
        for tag, attrs in self.parser.elements:
            self.assertNotIn("style", attrs, msg=f"inline style em <{tag}>")
            self.assertFalse(
                any(name.lower().startswith("on") for name in attrs),
                msg=f"event handler inline em <{tag}>",
            )

    def test_accessibility_guards_exist(self):
        self.assertRegex(self.css, r":focus-visible\s*\{")
        self.assertRegex(self.css, r"prefers-reduced-motion:\s*reduce")
        images = [attrs for tag, attrs in self.parser.elements if tag == "img"]
        self.assertTrue(images)
        self.assertTrue(all(attrs.get("alt", "").strip() for attrs in images))

    def test_layout_does_not_force_horizontal_overflow(self):
        viewport_floor = re.compile(r"(?:html|body)\s*\{[^}]*min-width", re.DOTALL)
        self.assertIsNone(viewport_floor.search(self.css))


if __name__ == "__main__":
    unittest.main()
