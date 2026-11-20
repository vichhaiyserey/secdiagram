from __future__ import annotations

import unittest
from html.parser import HTMLParser
from pathlib import Path

from secdiagram_core import studio_ui

ASSET_DIR = Path(__file__).resolve().parents[1] / "secdiagram_core" / "studio_ui"
FOCUSABLE_TAGS = {"a", "button", "input", "select", "textarea"}


class _AssetParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.elements: list[tuple[str, dict[str, str]]] = []
        self.ids: set[str] = set()
        self.controls: list[dict[str, str]] = []
        self._open_labels = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._record(tag, attrs)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._record(tag, attrs)

    def _record(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key: value or "" for key, value in attrs}
        self.elements.append((tag, values))
        if values.get("id"):
            self.ids.add(values["id"])
        if tag == "label":
            self._open_labels += 1
        if tag in {"input", "select", "textarea"} and values.get("type", "").lower() != "hidden":
            labelled = bool(values.get("aria-label") or values.get("aria-labelledby") or self._open_labels)
            self.controls.append({**values, "_tag": tag, "_labelled": labelled})

    def handle_endtag(self, tag: str) -> None:
        if tag == "label" and self._open_labels:
            self._open_labels -= 1

    def by_id(self, element_id: str) -> dict[str, str]:
        for _tag, attrs in self.elements:
            if attrs.get("id") == element_id:
                return attrs
        raise AssertionError(f"missing element id={element_id}")


class StudioAccessibilityAssetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.html = (ASSET_DIR / "index.html").read_text(encoding="utf-8")
        cls.css = (ASSET_DIR / "app.css").read_text(encoding="utf-8")
        cls.parser = _AssetParser()
        cls.parser.feed(cls.html)

    def test_unknown_and_traversal_assets_are_rejected(self) -> None:
        for name in ("missing.js", "../server.py", "studio_ui/../app.js", ""):
            with self.subTest(name=name):
                with self.assertRaises(studio_ui.StudioAssetError):
                    studio_ui.read_asset(name)

    def test_document_language_and_landmarks(self) -> None:
        html = next(attrs for tag, attrs in self.parser.elements if tag == "html")
        self.assertEqual(html.get("lang"), "en")
        main = self.parser.by_id("main")
        self.assertEqual(main.get("tabindex"), "-1")
        navs = [attrs for tag, attrs in self.parser.elements if tag == "nav"]
        self.assertEqual(len(navs), 1)
        self.assertEqual(navs[0].get("aria-label"), "Studio sections")

    def test_skip_link_is_first_focusable(self) -> None:
        first = next(
            attrs
            for tag, attrs in self.parser.elements
            if tag in FOCUSABLE_TAGS
        )
        self.assertIn("skip-link", first.get("class", ""))
        self.assertEqual(first.get("href"), "#main")

    def test_primary_views_use_tab_semantics(self) -> None:
        tabs = [attrs for _tag, attrs in self.parser.elements if attrs.get("role") == "tab"]
        panels = [attrs for _tag, attrs in self.parser.elements if attrs.get("role") == "tabpanel"]
        self.assertEqual(len(tabs), 5)
        self.assertEqual(len(panels), 5)
        panel_ids = {panel.get("id") for panel in panels}
        tab_ids = {tab.get("id") for tab in tabs}
        for tab in tabs:
            self.assertIn(tab.get("aria-controls"), panel_ids)
            self.assertIn(tab.get("aria-selected"), {"true", "false"})
            self.assertIn(tab.get("tabindex"), {"0", "-1"})
            self.assertEqual(self.parser.by_id(tab["aria-controls"])["aria-labelledby"], tab["id"])
            self.assertEqual(tab.get("tabindex"), "0" if tab["aria-selected"] == "true" else "-1")
        for panel in panels:
            self.assertIn(panel.get("aria-labelledby"), tab_ids)
        selected = [tab for tab in tabs if tab.get("aria-selected") == "true"]
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0].get("tabindex"), "0")
        self.assertEqual(selected[0].get("id"), "tab-dashboard")

    def test_live_regions_exist(self) -> None:
        live = [
            attrs
            for _tag, attrs in self.parser.elements
            if attrs.get("role") in {"status", "alert"} and attrs.get("aria-live")
        ]
        self.assertTrue(any(attrs.get("role") == "status" and attrs.get("aria-live") == "polite" for attrs in live))
        self.assertTrue(any(attrs.get("role") == "alert" and attrs.get("aria-live") == "assertive" for attrs in live))

    def test_form_controls_have_labels(self) -> None:
        self.assertTrue(self.parser.controls)
        for control in self.parser.controls:
            for reference in control.get("aria-labelledby", "").split():
                self.assertIn(reference, self.parser.ids, f"dangling control label: {reference}")
            self.assertTrue(
                control["_labelled"],
                f"{control['_tag']} #{control.get('id') or control.get('name') or '?'} is unlabelled",
            )

    def test_progress_and_toggle_attributes(self) -> None:
        progress = next(
            attrs
            for _tag, attrs in self.parser.elements
            if attrs.get("role") == "progressbar"
        )
        self.assertEqual(progress.get("aria-valuemin"), "0")
        self.assertEqual(progress.get("aria-valuemax"), "5")
        self.assertEqual(progress.get("aria-valuenow"), "0")

        source = self.parser.by_id("show-source")
        self.assertEqual(source.get("aria-expanded"), "false")
        self.assertEqual(source.get("aria-controls"), "mermaid-source")

        detail = self.parser.by_id("detail-seg")
        self.assertEqual(detail.get("role"), "group")
        pressed = [
            attrs
            for _tag, attrs in self.parser.elements
            if attrs.get("data-detail") and attrs.get("aria-pressed") == "true"
        ]
        self.assertEqual(len(pressed), 1)

    def test_no_external_studio_assets(self) -> None:
        for tag, attrs in self.parser.elements:
            for key in ("src", "href", "action"):
                value = attrs.get(key, "")
                self.assertFalse(
                    value.startswith(("http://", "https://")),
                    f"external asset on <{tag}>: {value}",
                )

    def test_css_provides_focus_and_motion_controls(self) -> None:
        self.assertIn(":focus-visible", self.css)
        self.assertIn("prefers-reduced-motion", self.css)
        self.assertIn(".skip-link", self.css)
        self.assertIn("outline", self.css)


if __name__ == "__main__":
    unittest.main()
