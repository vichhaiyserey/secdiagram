"""Unit tests for secret and path redaction helpers."""

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
    def test_empty_string(self) -> None:
        self.assertEqual(redact_secrets(""), "")
        self.assertEqual(sanitize_path_text(""), "")

    def test_aws_credentials(self) -> None:
        text = "aws_key = AKIAIOSFODNN7EXAMPLE and session = ASIAIOSFODNN7EXAMPLE"
        redacted = redact_secrets(text)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", redacted)
        self.assertNotIn("ASIAIOSFODNN7EXAMPLE", redacted)
        self.assertIn(REDACTED, redacted)

    def test_github_tokens(self) -> None:
        for prefix in ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"):
            token = f"{prefix}1234567890abcdef1234567890abcdef1234"
            line = f'token = "{token}"'
            self.assertNotIn(token, redact_secrets(line))
        pat = "github_pat_11AAAAAAA012345678901234567890123456789012345678901234567890"
        self.assertNotIn(pat, redact_secrets(f'pat = "{pat}"'))

    def test_gitlab_tokens(self) -> None:
        token = "glpat-abcdef12345678901234"
        self.assertNotIn(token, redact_secrets(f'token = "{token}"'))
        runner_token = "glrt-abcdef12345678901234"
        self.assertNotIn(runner_token, redact_secrets(f'runner = "{runner_token}"'))

    def test_slack_tokens(self) -> None:
        bot = "xoxb-1234567890-123456789012-abcdef123456"
        app = "xapp-1234567890-123456789012-abcdef123456"
        self.assertNotIn(bot, redact_secrets(f'slack_bot = "{bot}"'))
        self.assertNotIn(app, redact_secrets(f'slack_app = "{app}"'))

    def test_openai_and_anthropic_tokens(self) -> None:
        openai_proj = "sk-proj-1234567890abcdef1234567890abcdef"
        anthropic = "sk-ant-api03-1234567890abcdef1234567890abcdef"
        stripe = "sk_live_1234567890abcdef1234"
        self.assertNotIn(openai_proj, redact_secrets(f'key = "{openai_proj}"'))
        self.assertNotIn(anthropic, redact_secrets(f'key = "{anthropic}"'))
        self.assertNotIn(stripe, redact_secrets(f'key = "{stripe}"'))

    def test_google_and_sendgrid_tokens(self) -> None:
        google = "AIzaSyD-1234567890abcdef1234567890abcdef"
        sendgrid = "SG.1234567890abcdef12.1234567890abcdef12"
        self.assertNotIn(google, redact_secrets(f'google_key = "{google}"'))
        self.assertNotIn(sendgrid, redact_secrets(f'sg = "{sendgrid}"'))

    def test_jwt_token(self) -> None:
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozG4B1s"
        redacted = redact_secrets(f'bearer = "{jwt}"')
        self.assertNotIn(jwt, redacted)
        self.assertIn(REDACTED, redacted)

    def test_pypi_npm_tokens(self) -> None:
        pypi = "pypi-AgEIcHlwaS5vcmcCJDEyMzQ1Njc4LTBhYmMtZGVmMC0xMjM0LTU2Nzg5MGFiY2RlZg"
        npm = "npm_1234567890abcdef1234567890abcdef1234"
        self.assertNotIn(pypi, redact_secrets(f'pypi = "{pypi}"'))
        self.assertNotIn(npm, redact_secrets(f'npm = "{npm}"'))

    def test_private_key_blocks(self) -> None:
        rsa = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
        openssh = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNza...\n-----END OPENSSH PRIVATE KEY-----"
        self.assertEqual(redact_secrets(rsa), REDACTED)
        self.assertEqual(redact_secrets(openssh), REDACTED)

    def test_embedded_url_credentials(self) -> None:
        url = "postgres://appuser:super_secret_pw123@db.internal:5432/mydb"
        redacted = redact_secrets(f'db_url = "{url}"')
        self.assertNotIn("super_secret_pw123", redacted)
        self.assertIn("postgres://appuser:[REDACTED]@db.internal:5432/mydb", redacted)

        https_url = "https://admin:my-secret-token@api.example.com/v1"
        redacted_https = redact_secrets(https_url)
        self.assertNotIn("my-secret-token", redacted_https)
        self.assertIn("https://admin:[REDACTED]@api.example.com/v1", redacted_https)

    def test_authorization_headers(self) -> None:
        bearer = 'Authorization: Bearer 1234567890abcdef1234567890'
        basic = 'authorization: basic YWRtaW46cGFzc3dvcmQxMjM='
        token_auth = 'Authorization = Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b'
        self.assertNotIn("1234567890abcdef1234567890", redact_secrets(bearer))
        self.assertNotIn("YWRtaW46cGFzc3dvcmQxMjM=", redact_secrets(basic))
        self.assertNotIn("9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b", redact_secrets(token_auth))

    def test_quoted_assignment_with_spaces_and_special_chars(self) -> None:
        line1 = 'SECRET_KEY = "my very secret phrase with spaces!"'
        redacted1 = redact_secrets(line1)
        self.assertNotIn("my very secret phrase with spaces!", redacted1)
        self.assertEqual(redacted1, f'SECRET_KEY = "{REDACTED}"')

        line2 = "password = 'semi;colon,comma'"
        redacted2 = redact_secrets(line2)
        self.assertNotIn("semi;colon,comma", redacted2)
        self.assertEqual(redacted2, f"password = '{REDACTED}'")

    def test_unquoted_assignment(self) -> None:
        line = "DB_PASSWORD=my_database_password_123"
        redacted = redact_secrets(line)
        self.assertNotIn("my_database_password_123", redacted)
        self.assertEqual(redacted, f"DB_PASSWORD={REDACTED}")

    def test_redact_snippet_line(self) -> None:
        snippet = "    api_key = 'sk-proj-abcdef1234567890abcdef'"
        redacted = redact_snippet_line(snippet)
        self.assertNotIn("abcdef1234567890abcdef", redacted)
        self.assertIn(REDACTED, redacted)

    def test_sanitize_path_text(self) -> None:
        root = Path("/tmp/my-repo").resolve()
        inside = str(root / "secdiagram_core" / "cli.py")
        sanitized_inside = sanitize_path_text(inside, root)
        self.assertEqual(sanitized_inside, "./secdiagram_core/cli.py")
        # Reports must be byte-identical across platforms (determinism):
        # the forward-slash spelling of an inside path resolves the same way.
        self.assertEqual(
            sanitize_path_text(inside.replace("\\", "/"), root),
            "./secdiagram_core/cli.py",
        )

        outside_unix = "/etc/shadow"
        self.assertEqual(sanitize_path_text(outside_unix, root), "[external-path]")

        windows_drive = "C:\\Windows\\System32\\config"
        self.assertEqual(sanitize_path_text(windows_drive, root), "[external-path]")

        windows_unc = "\\\\server\\share\\secret.txt"
        self.assertEqual(sanitize_path_text(windows_unc, root), "[external-path]")

        relative_path = "secdiagram_core/model.py"
        self.assertEqual(sanitize_path_text(relative_path, root), relative_path)

        self.assertEqual(sanitize_path_text("/.ssh/id_rsa", root), "[external-path]")
        self.assertEqual(sanitize_path_text("/../etc/passwd", root), "[external-path]")

    def test_sanitize_url_path_keeps_routes(self) -> None:
        self.assertEqual(sanitize_url_path("/api/scan"), "/api/scan")
        self.assertEqual(sanitize_url_path("/api/v1/findings"), "/api/v1/findings")
        self.assertEqual(len(sanitize_url_path("/a" * 5000)), 512)
        self.assertNotIn("ghp_" + "a" * 36, sanitize_url_path("/x/ghp_" + "a" * 36))

    def test_key_assignment_regex_is_linear(self) -> None:
        # Regression: an unbounded key pattern made these inputs quadratic
        # ('a.' * 4000 took ~3s). 200k chars must finish well under a second.
        hostile_inputs = (
            "a." * 100_000,
            "a-" * 100_000,
            "token." * 30_000,
            "x" * 200_000,
            "-----BEGIN PRIVATE KEY-----" * 7_000,
        )
        for hostile in hostile_inputs:
            start = time.perf_counter()
            redact_secrets(hostile)
            # Generous ceiling: guards against quadratic blow-ups (orders of
            # magnitude slower), not absolute speed, so it must not flake on
            # loaded or slower CI machines.
            self.assertLess(time.perf_counter() - start, 2.5, hostile[:12])

    def test_dotted_and_prefixed_keys_still_redacted(self) -> None:
        self.assertEqual(redact_secrets("app.db.password=hunter2hunter2"), f"app.db.password={REDACTED}")
        self.assertEqual(redact_secrets("x;DB_PASSWORD=hunter2hunter2"), f"x;DB_PASSWORD={REDACTED}")

    def test_url_credentials_edge_cases(self) -> None:
        self.assertEqual(redact_secrets("redis://:dummy-pass-123@localhost:6379/0"), f"redis://:{REDACTED}@localhost:6379/0")
        self.assertEqual(redact_secrets("postgres://u:p/ss@h/db"), f"postgres://u:{REDACTED}@h/db")
        self.assertEqual(redact_secrets("http://host:8080/path"), "http://host:8080/path")

    def test_multi_word_and_ssh2_private_keys(self) -> None:
        ssh2 = "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\nMOCKKEY\n---- END SSH2 ENCRYPTED PRIVATE KEY ----"
        pem = "-----BEGIN SSH2 ENCRYPTED PRIVATE KEY-----\nMOCKKEY\n-----END SSH2 ENCRYPTED PRIVATE KEY-----"
        self.assertEqual(redact_secrets(ssh2), REDACTED)
        self.assertEqual(redact_secrets(pem), REDACTED)

    def test_benign_token_like_keys_are_not_redacted(self) -> None:
        for text in ("max_tokens=4096000 tokenizer=AutoTokenizer", "max_tokens=128000 exceeds context", "num_tokens: 123456"):
            self.assertEqual(redact_secrets(text), text)

    def test_sensitive_key_spellings_still_redacted(self) -> None:
        for key in ("githubToken", "apiKey", "x-api-key", "dbpassword", "client_secret", "access_token", "AUTH_TOKEN"):
            self.assertEqual(redact_secrets(f"{key}=mock_value_123"), f"{key}={REDACTED}")
        self.assertEqual(redact_secrets("max_tokens=password=mock_value_123"), f"max_tokens=password={REDACTED}")

    def test_new_patterns_are_linear(self) -> None:
        hostile_inputs = (
            "a://b:" * 30_000,
            "redis://:" * 25_000,
            "x_tokens=" * 25_000,
            "tokens=tokens=tokens" * 10_000,
            "token='" * 30_000,
            "---- BEGIN A PRIVATE KEY ----" * 6_000,
        )
        for hostile in hostile_inputs:
            start = time.perf_counter()
            redact_secrets(hostile)
            # Generous ceiling: guards against quadratic blow-ups (orders of
            # magnitude slower), not absolute speed, so it must not flake on
            # loaded or slower CI machines.
            self.assertLess(time.perf_counter() - start, 2.5, hostile[:12])


if __name__ == "__main__":
    unittest.main()
