"""Automated WCAG 2.1 AA static accessibility & contrast ratio audit for the SOC dashboard."""

from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path
import re
import unittest

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


class _AccessibilityParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag.lower(), dict(attrs)))


def _hex_to_rgb(hex_color: str) -> tuple[int, int, int]:
    h = hex_color.lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def _relative_luminance(rgb: tuple[int, int, int]) -> float:
    def _channel(c: int) -> float:
        s = c / 255.0
        return s / 12.92 if s <= 0.03928 else ((s + 0.055) / 1.055) ** 2.4

    r, g, b = rgb
    return 0.2126 * _channel(r) + 0.7152 * _channel(g) + 0.0722 * _channel(b)


def _contrast_ratio(fg_hex: str, bg_hex: str) -> float:
    l1 = _relative_luminance(_hex_to_rgb(fg_hex))
    l2 = _relative_luminance(_hex_to_rgb(bg_hex))
    lighter, darker = max(l1, l2), min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


class TestAccessibility(unittest.TestCase):
    def setUp(self) -> None:
        self.html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
        self.css = (STATIC_DIR / "styles.css").read_text(encoding="utf-8")
        self.js = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
        self.parser = _AccessibilityParser()
        self.parser.feed(self.html)

    def test_document_language_viewport_and_landmarks(self) -> None:
        tag_names = {tag for tag, _ in self.parser.tags}
        for landmark in ("header", "nav", "main", "section", "footer", "h1"):
            self.assertIn(landmark, tag_names, f"Missing semantic landmark <{landmark}>")

        html_tags = [attrs for tag, attrs in self.parser.tags if tag == "html"]
        self.assertEqual(html_tags[0].get("lang"), "en")

        metas = [attrs for tag, attrs in self.parser.tags if tag == "meta" and attrs.get("name") == "viewport"]
        self.assertTrue(metas)
        content = (metas[0].get("content") or "").lower()
        self.assertNotIn("user-scalable=no", content)
        self.assertNotIn("maximum-scale=1", content)

    def test_skip_link_and_focusable_headings(self) -> None:
        links = [attrs for tag, attrs in self.parser.tags if tag == "a"]
        self.assertTrue(
            any(a.get("href") == "#main-content" and "skip-link" in (a.get("class") or "") for a in links),
            "Missing skip-to-main-content link.",
        )
        mains = [attrs for tag, attrs in self.parser.tags if tag == "main"]
        self.assertEqual(mains[0].get("id"), "main-content")

        h2s = [attrs for tag, attrs in self.parser.tags if tag == "h2" and attrs.get("id") == "incidents-heading"]
        self.assertEqual(h2s[0].get("tabindex"), "-1")

    def test_form_controls_have_explicit_labels_and_aria(self) -> None:
        labels_for = {attrs.get("for") for tag, attrs in self.parser.tags if tag == "label"}
        ids = {attrs.get("id") for _, attrs in self.parser.tags if attrs.get("id")}
        textareas = [attrs for tag, attrs in self.parser.tags if tag == "textarea"]
        self.assertTrue(textareas)
        for ta in textareas:
            self.assertIn(ta.get("id"), labels_for)
            desc = ta.get("aria-describedby")
            self.assertIn(desc, ids)

    def test_aria_live_busy_alert_and_pressed_states(self) -> None:
        has_live = any(attrs.get("aria-live") == "polite" for _, attrs in self.parser.tags)
        has_busy = any("aria-busy" in attrs for _, attrs in self.parser.tags)
        has_alert = any(attrs.get("role") == "alert" for _, attrs in self.parser.tags)
        filter_buttons = [
            attrs for tag, attrs in self.parser.tags
            if tag == "button" and "filter-btn" in (attrs.get("class") or "")
        ]
        self.assertTrue(has_live)
        self.assertTrue(has_busy)
        self.assertTrue(has_alert)
        self.assertGreaterEqual(len(filter_buttons), 4)
        for btn in filter_buttons:
            self.assertIn(btn.get("aria-pressed"), {"true", "false"})

    def test_wcag_aa_contrast_ratio_for_all_css_color_pairs(self) -> None:
        # Resolve CSS custom properties defined in :root.
        var_map = dict(re.findall(r"(--[a-zA-Z0-9-]+)\s*:\s*(#[0-9a-fA-F]{3,6})\s*;", self.css))

        def resolve(val: str) -> str | None:
            v = val.strip()
            if v.startswith("var("):
                name = v[4:-1].strip()
                return var_map.get(name)
            return v if v.startswith("#") else None

        checked = 0
        for selector, block in re.findall(r"([^{}]+)\{([^{}]+)\}", self.css):
            fg_m = re.search(r"(?<![a-z-])color\s*:\s*([^;]+);", block)
            bg_m = re.search(r"background-color\s*:\s*([^;]+);", block)
            if fg_m and bg_m:
                fg = resolve(fg_m.group(1))
                bg = resolve(bg_m.group(1))
                if fg and bg:
                    checked += 1
                    ratio = _contrast_ratio(fg, bg)
                    self.assertGreaterEqual(
                        ratio,
                        4.5,
                        f"WCAG AA contrast fail on '{selector.strip()}': {fg} on {bg} = {ratio:.2f}:1 (<4.5:1)",
                    )
        self.assertGreaterEqual(checked, 8, "Expected at least 8 CSS foreground/background pairs audited.")

    def test_touch_targets_focus_visible_reduced_motion_and_forced_colors(self) -> None:
        self.assertIn("min-height: 44px", self.css)
        self.assertIn(":focus-visible", self.css)
        self.assertIn("prefers-reduced-motion", self.css)
        self.assertIn("forced-colors", self.css)

    def test_js_avoids_unsafe_dom_apis(self) -> None:
        for unsafe in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"):
            self.assertNotIn(unsafe, self.js, f"Frontend JS must not use {unsafe}.")


if __name__ == "__main__":
    unittest.main()
