"""Exact redaction replacements, preserved context and safe counterparts."""

from __future__ import annotations

import time
import unittest
from pathlib import Path

from secdiagram_core.redaction import (
    REDACTED,
    redact_secrets,
    redact_snippet_line,
    sanitize_path_text,
    sanitize_url_path,
)


class RedactionTests(unittest.TestCase):
    def test_provider_tokens_in_neutral_text(self) -> None:
        # Token-shaped dummy values, never real credentials. A generic key=
        # assignment redactor must not satisfy these provider-recognition cases.
        cases = {
            **{f"aws-{p}": p + "MOCKTOKEN1234567" for p in ("AKIA", "ASIA")},
            **{
                f"github-{p}": p + "mocktoken" + "a" * 27
                for p in ("ghp_", "gho_", "ghu_", "ghs_", "ghr_")
            },
            "github-pat": "github_pat_" + "mock_token_" + "a" * 20,
            **{
                f"gitlab-{p}": p + "mock_token_" + "a" * 20
                for p in ("glpat-", "glptt-", "glrt-", "gloas-", "glagent-")
            },
            **{
                f"slack-{p}": p + "mocktoken-123456"
                for p in ("xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-", "xapp-")
            },
            **{
                f"ai-{p}": p + "mock_token_" + "a" * 20
                for p in (
                    "sk-",
                    "sk-proj-",
                    "sk-svcacct-",
                    "sk-admin-",
                    "sk-ant-api03-",
                    "sk-ant-admin01-",
                )
            },
            "stripe-secret": "sk_live_" + "mocktoken" + "a" * 8,
            "stripe-restricted": "rk_live_" + "mocktoken" + "a" * 8,
            "google": "AIza" + "mock_token_" + "a" * 25,
            "sendgrid": "SG." + "mocktoken" + "a" * 7 + "." + "mocktoken" + "a" * 7,
            "mailgun": "key-" + "mocktoken" + "a" * 23,
            "digitalocean": "dop_v1_" + "a" * 64,
            "pypi": "pypi-AgEIcHlwaS5vcmc" + "mock_token_" + "a" * 20,
            "npm": "npm_" + "mocktoken" + "a" * 27,
            **{f"shopify-{p}": p + "a" * 32 for p in ("shpat_", "shpca_", "shpss_")},
            "discord": "M" + "a" * 23 + "." + "b" * 6 + "." + "c" * 27,
            "telegram": "12345678:" + "mocktoken" + "a" * 26,
            "jwt": "eyJmockheader12345.mockpayload12345.mocksignature12345",
            "azure": "AccountKey=" + "a" * 40,
            **{f"vault-{p}": p + "mock_token_" + "a" * 20 for p in ("hvb.", "hvs.")},
            "databricks": "dapi" + "a" * 32,
            "postman": "PMAK-" + "a" * 24 + "-" + "b" * 34,
        }
        for provider, token in cases.items():
            with self.subTest(provider=provider, condition="recognized"):
                self.assertEqual(
                    redact_secrets(f"payload {token} tail"), f"payload {REDACTED} tail"
                )
            with self.subTest(provider=provider, condition="identifier-boundary"):
                near_miss = f"payload x{token} tail"
                self.assertEqual(redact_secrets(near_miss), near_miss)

    def test_private_key_blocks_preserve_surrounding_text(self) -> None:
        for begin, end in (
            ("-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"),
            ("-----BEGIN OPENSSH PRIVATE KEY-----", "-----END OPENSSH PRIVATE KEY-----"),
            (
                "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----",
                "---- END SSH2 ENCRYPTED PRIVATE KEY ----",
            ),
            (
                "-----BEGIN SSH2 ENCRYPTED PRIVATE KEY-----",
                "-----END SSH2 ENCRYPTED PRIVATE KEY-----",
            ),
        ):
            with self.subTest(begin=begin):
                block = f"{begin}\ndummy-private-key-body\n{end}"
                self.assertEqual(
                    redact_secrets(f"before\n{block}\nafter"), f"before\n{REDACTED}\nafter"
                )

    def test_url_credentials_preserve_scheme_user_host_and_path(self) -> None:
        for original, expected in (
            (
                "postgres://appuser:dummy-pass-123@db.internal:5432/mydb",
                f"postgres://appuser:{REDACTED}@db.internal:5432/mydb",
            ),
            (
                "https://admin:dummy-pass-123@api.example.com/v1",
                f"https://admin:{REDACTED}@api.example.com/v1",
            ),
            ("redis://:dummy-pass-123@localhost:6379/0", f"redis://:{REDACTED}@localhost:6379/0"),
            ("postgres://u:p/ss@h/db", f"postgres://u:{REDACTED}@h/db"),
            ("http://host:8080/path", "http://host:8080/path"),
        ):
            with self.subTest(url=original):
                self.assertEqual(redact_secrets(original), expected)

    def test_authorization_headers_preserve_the_header_and_scheme(self) -> None:
        for header in ("Authorization: Bearer", "authorization: basic", "Authorization = Token"):
            with self.subTest(header=header):
                self.assertEqual(
                    redact_secrets(f"{header} mock_header_value_12345"), f"{header} {REDACTED}"
                )

    def test_sensitive_assignments_preserve_keys_quotes_and_delimiters(self) -> None:
        cases = [
            ('SECRET_KEY = "dummy phrase with spaces!"', f'SECRET_KEY = "{REDACTED}"'),
            ("password = 'dummy;colon,comma'", f"password = '{REDACTED}'"),
            ("DB_PASSWORD=dummy_password_123", f"DB_PASSWORD={REDACTED}"),
            ("app.db.password=dummy_password_123", f"app.db.password={REDACTED}"),
            ("x;DB_PASSWORD=dummy_password_123", f"x;DB_PASSWORD={REDACTED}"),
            ("max_tokens=password=dummy_password_123", f"max_tokens=password={REDACTED}"),
        ]
        cases.extend(
            (f"{key}=mock_value_123", f"{key}={REDACTED}")
            for key in (
                "githubToken",
                "apiKey",
                "x-api-key",
                "dbpassword",
                "client_secret",
                "access_token",
                "AUTH_TOKEN",
            )
        )
        for original, expected in cases:
            with self.subTest(assignment=original):
                self.assertEqual(redact_secrets(original), expected)

    def test_benign_text_and_token_configuration_are_preserved(self) -> None:
        for text in (
            "",
            "ordinary application message",
            "max_tokens=4096000 tokenizer=AutoTokenizer",
            "max_tokens=128000 exceeds context",
            "num_tokens: 123456",
        ):
            with self.subTest(text=text):
                self.assertEqual(redact_secrets(text), text)
        self.assertEqual(sanitize_path_text(""), "")

    def test_redact_snippet_line_preserves_indentation_and_key(self) -> None:
        self.assertEqual(
            redact_snippet_line("    api_key = 'mock_value_12345'"), f"    api_key = '{REDACTED}'"
        )

    def test_sanitize_path_text(self) -> None:
        root = Path("/tmp/my-repo").resolve()
        inside = str(root / "secdiagram_core" / "cli.py")
        for original, expected in (
            (inside, "./secdiagram_core/cli.py"),
            (inside.replace("\\", "/"), "./secdiagram_core/cli.py"),
            ("/etc/shadow", "[external-path]"),
            ("C:\\Windows\\System32\\config", "[external-path]"),
            ("\\\\server\\share\\secret.txt", "[external-path]"),
            ("secdiagram_core/model.py", "secdiagram_core/model.py"),
            ("/.ssh/id_rsa", "[external-path]"),
            ("/../etc/passwd", "[external-path]"),
        ):
            with self.subTest(path=original):
                self.assertEqual(sanitize_path_text(original, root), expected)

    def test_sanitize_url_path_keeps_routes_and_caps_length(self) -> None:
        for route in ("/api/scan", "/api/v1/findings"):
            with self.subTest(route=route):
                self.assertEqual(sanitize_url_path(route), route)
        self.assertEqual(sanitize_url_path("/a" * 5000), ("/a" * 5000)[:512])
        token = "ghp_" + "mocktoken" + "a" * 27
        self.assertEqual(sanitize_url_path(f"/x/{token}"), f"/x/{REDACTED}")

    def test_hostile_inputs_do_not_trigger_quadratic_redaction(self) -> None:
        for hostile in (
            "a." * 100_000,
            "a-" * 100_000,
            "token." * 30_000,
            "x" * 200_000,
            "-----BEGIN PRIVATE KEY-----" * 7_000,
            "a://b:" * 30_000,
            "redis://:" * 25_000,
            "x_tokens=" * 25_000,
            "tokens=tokens=tokens" * 10_000,
            "token='" * 30_000,
            "---- BEGIN A PRIVATE KEY ----" * 6_000,
        ):
            with self.subTest(prefix=hostile[:28]):
                start = time.perf_counter()
                redact_secrets(hostile)
                # Retain the existing generous regression ceiling, not a benchmark.
                self.assertLess(time.perf_counter() - start, 2.5)


if __name__ == "__main__":
    unittest.main()
