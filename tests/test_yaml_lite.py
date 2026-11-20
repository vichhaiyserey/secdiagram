"""Tests for the minimal YAML skeleton parser used by IaC analyzers."""

from __future__ import annotations

import unittest

from secdiagram_core.yaml_lite import parse_yaml


class YamlLiteTests(unittest.TestCase):
    def test_nested_mappings(self) -> None:
        doc = parse_yaml("a:\n  b:\n    c: 1\nd: 2\n")[0]
        a = doc.child("a")
        self.assertIsNotNone(a)
        b = a.child("b")
        self.assertIsNotNone(b)
        self.assertEqual(b.child("c").value, "1")
        self.assertEqual(doc.child("d").value, "2")

    def test_block_scalars(self) -> None:
        doc = parse_yaml("run: |\n  echo one\n  echo two\nafter: x\n")[0]
        run = doc.child("run")
        self.assertEqual(run.block, "echo one\necho two")
        self.assertIsNone(run.value)
        self.assertEqual(doc.child("after").value, "x")

    def test_block_scalar_stops_at_dedent(self) -> None:
        doc = parse_yaml("steps:\n  - run: |\n      a\n      b\n  - uses: x\n")[0]
        steps = doc.child("steps")
        run = steps.children[0]
        self.assertEqual(run.key, "run")
        self.assertEqual(run.block, "a\nb")
        self.assertEqual(steps.children[1].key, "uses")
        self.assertEqual(steps.children[1].value, "x")

    def test_comments_and_blank_lines(self) -> None:
        doc = parse_yaml("# top\n\nkey: value # trailing\n#other: hidden\n")[0]
        self.assertEqual(doc.child("key").value, "value")
        self.assertIsNone(doc.child("other"))

    def test_comment_inside_quotes(self) -> None:
        doc = parse_yaml('key: "a # b"\n')[0]
        self.assertEqual(doc.child("key").value, "a # b")

    def test_quoted_values(self) -> None:
        doc = parse_yaml("a: \"true\"\nb: 'host'\n")[0]
        self.assertEqual(doc.child("a").value, "true")
        self.assertEqual(doc.child("b").value, "host")

    def test_list_items(self) -> None:
        doc = parse_yaml("items:\n  - alpha\n  - beta\n")[0]
        items = [child.value for child in doc.child("items").children]
        self.assertEqual(items, ["alpha", "beta"])

    def test_list_item_mapping_siblings(self) -> None:
        doc = parse_yaml("list:\n  - name: a\n  - name: b\n")[0]
        names = [child.value for child in doc.child("list").children if child.key == "name"]
        self.assertEqual(names, ["a", "b"])

    def test_multiple_documents(self) -> None:
        docs = parse_yaml("kind: A\n---\nkind: B\n")
        self.assertEqual(len(docs), 2)
        self.assertEqual(docs[0].child("kind").value, "A")
        self.assertEqual(docs[1].child("kind").value, "B")

    def test_template_marker(self) -> None:
        doc = parse_yaml("image: \"{{ .Values.image }}\"\n")[0]
        image = doc.child("image")
        self.assertTrue(image.template)
        self.assertEqual(image.value, "{{ .Values.image }}")

    def test_inline_flow_collections_kept_raw(self) -> None:
        doc = parse_yaml("capabilities: {add: [SYS_ADMIN]}\n")[0]
        self.assertEqual(doc.child("capabilities").value, "{add: [SYS_ADMIN]}")

    def test_colon_in_value_not_split(self) -> None:
        doc = parse_yaml("image: repo.example:5000/app:1.0\n")[0]
        self.assertEqual(doc.child("image").value, "repo.example:5000/app:1.0")

    def test_malformed_input_does_not_raise(self) -> None:
        malformed = "\n\t\t:\n  ]]\n  : :\nplain string\n"
        docs = parse_yaml(malformed)
        self.assertEqual(len(docs), 1)
        self.assertIsNone(docs[0].child("x"))
        recovered = parse_yaml(malformed + "valid: recovered\n")[0].child("valid")
        self.assertIsNotNone(recovered)
        self.assertEqual(recovered.value, "recovered")
        self.assertEqual(recovered.line, 6)

    def test_empty_input(self) -> None:
        self.assertEqual(parse_yaml(""), [])
        self.assertEqual(parse_yaml("# only a comment\n"), [])


if __name__ == "__main__":
    unittest.main()
