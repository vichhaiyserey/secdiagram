"""Minimal indentation-aware YAML skeleton parser (standard library only).

This is deliberately *not* a YAML implementation. It supports the subset of
block-style YAML that appears in Docker Compose files, Kubernetes manifests,
GitHub Actions workflows and GitLab CI pipelines: nested mappings, block
sequences, plain and quoted scalars, block scalars (``|`` / ``>``), comments,
multiple documents (``---``) and Helm/Jinja templating markers. Flow
collections (``{a: b}`` / ``[a, b]``) are preserved as opaque strings.

The parser is deterministic, never executes anything and never raises on
malformed input: lines it cannot interpret are skipped. List items are
represented by their first mapping entry (or a scalar node), which is
sufficient for security checks that match on mapping keys.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field

_BLOCK_SCALAR_RE = re.compile(r"^(?:[|>])[0-9]*[+-]?$")


@dataclass(slots=True)
class YamlNode:
    indent: int
    key: str | None
    value: str | None
    line: int
    block: str | None = None
    template: bool = False
    children: list[YamlNode] = field(default_factory=list)

    def child(self, key: str) -> YamlNode | None:
        for item in self.children:
            if item.key == key:
                return item
        return None

    def text(self) -> str:
        """Combined scalar text (inline value plus block content)."""
        parts: list[str] = []
        if self.value is not None:
            parts.append(self.value)
        if self.block:
            parts.append(self.block)
        return "\n".join(parts)


def _indent_of(line: str) -> int:
    stripped = line.lstrip(" ")
    return len(line) - len(stripped)


def _strip_comment(line: str) -> str:
    quote: str | None = None
    for index, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == "#" and (index == 0 or line[index - 1] in " \t"):
            return line[:index]
    return line


def _split_kv(content: str) -> tuple[str | None, str | None]:
    """Split ``key: value`` at the first ``:`` that is followed by space/EOL."""
    quote: str | None = None
    for index, ch in enumerate(content):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == ":" and (index + 1 == len(content) or content[index + 1] in " \t"):
            key = content[:index].strip().strip("'\"")
            return key or None, content[index + 1 :].strip()
    return None, content


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _attach(stack: list[YamlNode], node: YamlNode) -> None:
    while len(stack) > 1 and stack[-1].indent >= node.indent:
        stack.pop()
    stack[-1].children.append(node)
    stack.append(node)


def parse_yaml(text: str) -> list[YamlNode]:
    """Parse *text* into a list of document roots (synthetic nodes, indent -1)."""
    docs: list[YamlNode] = []
    doc = YamlNode(indent=-1, key=None, value=None, line=1)
    stack: list[YamlNode] = [doc]
    block_node: YamlNode | None = None
    block_indent = -1
    block_parts: list[str] = []

    def flush_block() -> None:
        nonlocal block_node, block_parts
        if block_node is not None:
            block_node.block = "\n".join(block_parts) or None
        block_node = None
        block_parts = []

    for number, raw in enumerate(text.splitlines(), start=1):
        if block_node is not None:
            if not raw.strip():
                block_parts.append("")
                continue
            if _indent_of(raw) > block_indent:
                block_parts.append(raw.strip())
                continue
            flush_block()
        content = _strip_comment(raw.replace("\t", "    ")).strip()
        if not content:
            continue
        if content in {"---", "..."}:
            if content == "---":
                docs.append(doc)
                doc = YamlNode(indent=-1, key=None, value=None, line=number)
                stack = [doc]
            continue
        indent = _indent_of(raw.replace("\t", "    "))
        while content.startswith("- ") or content == "-":
            content = content[2:].lstrip()
            indent += 2
        key, value = _split_kv(content)
        node = YamlNode(indent=indent, key=key, value=None, line=number)
        if value:
            node.value = _unquote(value)
            node.template = "{{" in node.value
            if _BLOCK_SCALAR_RE.match(value):
                node.value = None
                block_node = node
                block_indent = indent
                block_parts = []
        _attach(stack, node)
    flush_block()
    docs.append(doc)
    return [entry for entry in docs if entry.children]


def iter_nodes(node: YamlNode, path: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], YamlNode]]:
    """Depth-first walk yielding ``(key path, child)`` pairs in document order."""
    for child in node.children:
        key_path = path + (child.key,) if child.key else path
        yield key_path, child
        yield from iter_nodes(child, key_path)


def walk(node: YamlNode) -> Iterator[YamlNode]:
    """Depth-first walk yielding every descendant node (document order)."""
    for child in node.children:
        yield child
        yield from walk(child)
