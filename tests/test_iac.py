"""Tests for infrastructure-as-code analyzers (Docker, Compose, CI, K8s, Terraform)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from secdiagram_core.discover import RepoInfo
from secdiagram_core.iac import analyze_iac
from secdiagram_core.model import Finding, Graph


def _run(files: dict[str, str]) -> tuple[Graph, list[Finding]]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for rel, text in files.items():
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        repo = RepoInfo(root=root, name="repo", rel_files=sorted(files))
        graph = Graph()
        findings = analyze_iac(graph, repo)
    return graph, findings


def _rules(files: dict[str, str]) -> set[tuple[str, int]]:
    _, findings = _run(files)
    return {(f.metadata["rule_id"], f.evidence[0].line) for f in findings}


def _titles(files: dict[str, str]) -> set[str]:
    _, findings = _run(files)
    return {f.title for f in findings}


class DockerfileRuleTests(unittest.TestCase):
    def test_unpinned_base_images(self) -> None:
        rules = _rules(
            {"Dockerfile": "FROM python\nFROM alpine:latest\n"}
        )
        self.assertIn(("IAC-DOCKER-001", 1), rules)
        self.assertIn(("IAC-DOCKER-001", 2), rules)

    def test_pinned_base_image_not_flagged(self) -> None:
        rules = _rules(
            {
                "Dockerfile": (
                    "FROM python:3.11-slim@sha256:"
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
                )
            }
        )
        self.assertNotIn(("IAC-DOCKER-001", 1), rules)

    def test_stage_alias_is_case_insensitive(self) -> None:
        rules = _rules({"Dockerfile": "FROM python:3.11 as builder\n"})
        self.assertNotIn(("IAC-DOCKER-001", 1), rules)

    def test_remote_add_and_piped_shell(self) -> None:
        rules = _rules(
            {
                "Dockerfile": (
                    "FROM alpine:3.19\n"
                    "ADD https://example.com/install.sh /tmp/install.sh\n"
                    "RUN curl -sSL https://x.example | sh\n"
                )
            }
        )
        self.assertIn(("IAC-DOCKER-002", 2), rules)
        self.assertIn(("IAC-DOCKER-003", 3), rules)

    def test_env_and_arg_secrets(self) -> None:
        rules = _rules(
            {
                "Dockerfile": (
                    "FROM alpine:3.19\n"
                    "ENV API_KEY=super_secret_value\n"
                    "ARG DB_PASSWORD=hunter2hunter\n"
                    "ENV EXAMPLE_TOKEN=changeme\n"
                )
            }
        )
        self.assertIn(("IAC-DOCKER-004", 2), rules)
        self.assertIn(("IAC-DOCKER-005", 3), rules)
        self.assertNotIn(("IAC-DOCKER-004", 4), rules)

    def test_permissions_and_sudo(self) -> None:
        rules = _rules(
            {
                "Dockerfile": (
                    "FROM alpine:3.19\n"
                    "RUN chmod 777 /data\n"
                    "RUN sudo make install\n"
                )
            }
        )
        self.assertIn(("IAC-DOCKER-006", 2), rules)
        self.assertIn(("IAC-DOCKER-007", 3), rules)

    def test_runs_as_root_and_non_root(self) -> None:
        rules = _rules({"Dockerfile": "FROM alpine:3.19\n"})
        self.assertIn(("IAC-DOCKER-008", 1), rules)
        rules = _rules({"Dockerfile": "FROM alpine:3.19\nUSER app\n"})
        self.assertNotIn("IAC-DOCKER-008", {rule for rule, _ in rules})

    def test_node_attrs(self) -> None:
        graph, _ = _run({"Dockerfile": "FROM alpine:3.19\nEXPOSE 8080 9090\nUSER app\n"})
        node = next(n for n in graph.nodes.values() if n.feature == "infrastructure")
        self.assertEqual(node.attrs["base_images"], ["alpine:3.19"])
        self.assertEqual(node.attrs["user"], "app")
        self.assertEqual(node.attrs["exposed_ports"], ["8080", "9090"])


class ComposeRuleTests(unittest.TestCase):
    def test_four_space_indentation_supported(self) -> None:
        graph, findings = _run(
            {
                "docker-compose.yml": (
                    "services:\n"
                    "    api:\n"
                    "        image: sample/app:latest\n"
                    "        privileged: true\n"
                )
            }
        )
        rules = {(f.metadata["rule_id"], f.evidence[0].line) for f in findings}
        self.assertIn(("IAC-COMPOSE-001", 3), rules)
        self.assertIn(("IAC-COMPOSE-002", 4), rules)
        self.assertTrue(any(n.kind == "service" and n.name == "api" for n in graph.nodes.values()))

    def test_elevated_runtime_settings(self) -> None:
        rules = _rules(
            {
                "compose.yml": (
                    "services:\n"
                    "  api:\n"
                    "    image: app:1.0\n"
                    "    privileged: true\n"
                    "    network_mode: host\n"
                    "    pid: host\n"
                    "    ipc: host\n"
                    "    userns_mode: host\n"
                    "    user: root\n"
                )
            }
        )
        self.assertIn(("IAC-COMPOSE-002", 4), rules)
        self.assertIn(("IAC-COMPOSE-003", 5), rules)
        self.assertIn(("IAC-COMPOSE-004", 6), rules)
        self.assertIn(("IAC-COMPOSE-005", 7), rules)
        self.assertIn(("IAC-COMPOSE-006", 8), rules)
        self.assertIn(("IAC-COMPOSE-011", 9), rules)

    def test_socket_caps_profile_and_mounts(self) -> None:
        rules = _rules(
            {
                "compose.yml": (
                    "services:\n"
                    "  api:\n"
                    "    image: app:1.0\n"
                    "    volumes:\n"
                    "      - /var/run/docker.sock:/var/run/docker.sock\n"
                    "      - /etc:/host-etc\n"
                    "    cap_add:\n"
                    "      - SYS_ADMIN\n"
                    "    security_opt:\n"
                    "      - seccomp=unconfined\n"
                )
            }
        )
        self.assertIn(("IAC-COMPOSE-007", 5), rules)
        self.assertIn(("IAC-COMPOSE-010", 6), rules)
        self.assertIn(("IAC-COMPOSE-008", 7), rules)
        self.assertIn(("IAC-COMPOSE-009", 9), rules)

    def test_env_secrets(self) -> None:
        rules = _rules(
            {
                "compose.yml": (
                    "services:\n"
                    "  api:\n"
                    "    image: app:1.0\n"
                    "    environment:\n"
                    "      - API_KEY=literal-value-1\n"
                    "      - SECRET_TOKEN\n"
                    "      DB_PASSWORD: hunter2hunter\n"
                    "      SAFE_TOKEN: ${SAFE_TOKEN}\n"
                )
            }
        )
        self.assertIn(("IAC-COMPOSE-012", 5), rules)
        self.assertIn(("IAC-COMPOSE-012", 7), rules)
        self.assertEqual(
            len([rule for rule, _ in rules if rule == "IAC-COMPOSE-012"]),
            2,
        )

    def test_pinned_image_not_flagged(self) -> None:
        rules = _rules({"compose.yml": "services:\n  api:\n    image: app:1.2.3\n"})
        self.assertNotIn("IAC-COMPOSE-001", {rule for rule, _ in rules})


class GitHubWorkflowRuleTests(unittest.TestCase):
    def test_write_all_permissions(self) -> None:
        rules = _rules(
            {
                ".github/workflows/ci.yml": (
                    "on: push\n"
                    "permissions: write-all\n"
                    "jobs:\n"
                    "  build:\n"
                    "    permissions: write-all\n"
                    "    steps:\n"
                    "      - run: echo ok\n"
                )
            }
        )
        self.assertIn(("IAC-CI-001", 2), rules)
        self.assertIn(("IAC-CI-001", 5), rules)

    def test_action_pinning(self) -> None:
        rules = _rules(
            {
                ".github/workflows/ci.yml": (
                    "on: push\n"
                    "jobs:\n"
                    "  build:\n"
                    "    steps:\n"
                    "      - uses: actions/checkout@v4\n"
                    "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
                    "      - uses: ./local-action\n"
                )
            }
        )
        self.assertIn(("IAC-CI-002", 5), rules)
        self.assertEqual(
            len([rule for rule, _ in rules if rule == "IAC-CI-002"]),
            1,
        )

    def test_privileged_triggers(self) -> None:
        rules = _rules(
            {
                ".github/workflows/ci.yml": (
                    "on:\n"
                    "  pull_request_target:\n"
                    "  push:\n"
                )
            }
        )
        self.assertIn(("IAC-CI-004", 2), rules)

    def test_inline_trigger_list(self) -> None:
        rules = _rules(
            {".github/workflows/ci.yml": "on: [push, workflow_run]\n"}
        )
        self.assertIn(("IAC-CI-005", 1), rules)

    def test_multiline_run_injection(self) -> None:
        rules = _rules(
            {
                ".github/workflows/ci.yml": (
                    "on: pull_request\n"
                    "jobs:\n"
                    "  build:\n"
                    "    steps:\n"
                    "      - run: |\n"
                    "          echo \"PR title: ${{ github.event.head_commit.message }}\"\n"
                    "          echo \"token: ${{ secrets.GITHUB_TOKEN }}\"\n"
                )
            }
        )
        self.assertIn(("IAC-CI-006", 5), rules)
        self.assertIn(("IAC-CI-007", 5), rules)

    def test_piped_shell_in_run(self) -> None:
        rules = _rules(
            {".github/workflows/ci.yml": "on: push\njobs:\n  build:\n    steps:\n      - run: curl -s https://x | sh\n"}
        )
        self.assertIn(("IAC-CI-003", 5), rules)

    def test_node_attrs(self) -> None:
        graph, _ = _run(
            {
                ".github/workflows/ci.yml": (
                    "on:\n"
                    "  push:\n"
                    "  pull_request:\n"
                    "jobs:\n"
                    "  build:\n"
                    "    steps:\n"
                    "      - uses: actions/checkout@v4\n"
                    "      - run: echo ${{ secrets.GITHUB_TOKEN }}\n"
                )
            }
        )
        node = next(n for n in graph.nodes.values() if n.kind == "workflow")
        self.assertEqual(node.attrs["triggers"], ["pull_request", "push"])
        self.assertEqual(node.attrs["actions"], ["actions/checkout@v4"])
        self.assertEqual(node.attrs["secrets"], ["GITHUB_TOKEN"])


class KubernetesRuleTests(unittest.TestCase):
    def test_pod_security_battery(self) -> None:
        rules = _rules(
            {
                "k8s/workload.yaml": (
                    "apiVersion: apps/v1\n"          # 1
                    "kind: Deployment\n"             # 2
                    "metadata:\n"                    # 3
                    "  name: api\n"                  # 4
                    "spec:\n"                        # 5
                    "  template:\n"                  # 6
                    "    spec:\n"                    # 7
                    "      hostNetwork: true\n"      # 8
                    "      hostPID: true\n"          # 9
                    "      hostIPC: true\n"          # 10
                    "      automountServiceAccountToken: true\n"  # 11
                    "      volumes:\n"               # 12
                    "        - name: data\n"         # 13
                    "          hostPath:\n"          # 14
                    "            path: /var/data\n"  # 15
                    "      containers:\n"            # 16
                    "        - name: app\n"          # 17
                    "          image: app:latest\n"  # 18
                    "          securityContext:\n"   # 19
                    "            privileged: true\n"  # 20
                    "            runAsUser: 0\n"     # 21
                    "            runAsNonRoot: false\n"  # 22
                    "            allowPrivilegeEscalation: true\n"  # 23
                    "            readOnlyRootFilesystem: false\n"  # 24
                    "            seccompProfile:\n"  # 25
                    "              type: Unconfined\n"  # 26
                    "            capabilities:\n"    # 27
                    "              add:\n"          # 28
                    "                - SYS_ADMIN\n"  # 29
                )
            }
        )
        self.assertEqual(
            {rule for rule, _ in rules},
            {
                "IAC-K8S-001",
                "IAC-K8S-002",
                "IAC-K8S-003",
                "IAC-K8S-004",
                "IAC-K8S-005",
                "IAC-K8S-006",
                "IAC-K8S-007",
                "IAC-K8S-008",
                "IAC-K8S-009",
                "IAC-K8S-010",
                "IAC-K8S-011",
                "IAC-K8S-012",
                "IAC-K8S-013",
            },
        )
        self.assertIn(("IAC-K8S-001", 20), rules)
        self.assertIn(("IAC-K8S-011", 14), rules)
        self.assertIn(("IAC-K8S-013", 18), rules)

    def test_run_as_user_ten_not_flagged(self) -> None:
        rules = _rules(
            {
                "k8s/deployment.yaml": (
                    "kind: Deployment\n"
                    "spec:\n"
                    "  template:\n"
                    "    spec:\n"
                    "      containers:\n"
                    "        - securityContext:\n"
                    "            runAsUser: 10\n"
                )
            }
        )
        self.assertNotIn("IAC-K8S-005", {rule for rule, _ in rules})

    def test_configmap_ignored(self) -> None:
        rules = _rules(
            {
                "k8s/configmap.yaml": (
                    "kind: ConfigMap\n"
                    "data:\n"
                    "  privileged: \"true\"\n"
                    "  runAsUser: \"0\"\n"
                )
            }
        )
        self.assertEqual(rules, set())

    def test_multi_document_file(self) -> None:
        graph, findings = _run(
            {
                "k8s/all.yaml": (
                    "kind: ConfigMap\n"
                    "---\n"
                    "kind: Pod\n"
                    "spec:\n"
                    "  containers:\n"
                    "    - image: app:latest\n"
                )
            }
        )
        rules = {(f.metadata["rule_id"], f.evidence[0].line) for f in findings}
        self.assertEqual(rules, {("IAC-K8S-013", 6)})
        k8s_nodes = [n for n in graph.nodes.values() if n.feature == "infrastructure"]
        self.assertEqual(len(k8s_nodes), 1)
        self.assertEqual(k8s_nodes[0].name, "pod/all.yaml")

    def test_supply_chain_category_is_hyphenated(self) -> None:
        _, findings = _run(
            {"k8s/deployment.yaml": "kind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - image: app:latest\n"}
        )
        self.assertEqual([f.category for f in findings], ["supply-chain"])

    def test_metadata_name_used_for_node(self) -> None:
        graph, _ = _run(
            {
                "k8s/deployment.yaml": (
                    "kind: Deployment\n"
                    "metadata:\n"
                    "  name: sample-api\n"
                )
            }
        )
        node = next(n for n in graph.nodes.values() if n.feature == "infrastructure")
        self.assertEqual(node.name, "deployment/sample-api")
        self.assertEqual(node.attrs["name"], "sample-api")


class TerraformRuleTests(unittest.TestCase):
    def test_cloud_battery(self) -> None:
        rules = _rules(
            {
                "terraform/main.tf": (
                    "resource \"aws_security_group_rule\" \"open\" {\n"
                    "  cidr_blocks = [\"0.0.0.0/0\"]\n"
                    "}\n"
                    "resource \"aws_s3_bucket\" \"b\" {\n"
                    "  acl = \"public-read\"\n"
                    "}\n"
                    "resource \"aws_db_instance\" \"db\" {\n"
                    "  publicly_accessible = true\n"
                    "  storage_encrypted = false\n"
                    "}\n"
                    "resource \"aws_s3_bucket_public_access_block\" \"b\" {\n"
                    "  block_public_acls = false\n"
                    "}\n"
                    "data \"aws_iam_policy_document\" \"p\" {\n"
                    "  statement {\n"
                    "    actions = [\"*\"]\n"
                    "  }\n"
                    "}\n"
                )
            }
        )
        self.assertIn(("IAC-TF-001", 2), rules)
        self.assertIn(("IAC-TF-002", 5), rules)
        self.assertIn(("IAC-TF-004", 8), rules)
        self.assertIn(("IAC-TF-003", 9), rules)
        self.assertIn(("IAC-TF-005", 12), rules)
        self.assertIn(("IAC-TF-006", 16), rules)

    def test_hardcoded_secret_literal(self) -> None:
        rules = _rules({"terraform/main.tf": 'resource "x" "y" {\n  password = "super_secret_pw"\n}\n'})
        self.assertIn(("IAC-TF-007", 2), rules)

    def test_heredoc_secret(self) -> None:
        rules = _rules(
            {
                "terraform/main.tf": (
                    "resource \"x\" \"y\" {\n"
                    "  password = <<EOF\n"
                    "  s3cret_value_here\n"
                    "EOF\n"
                    "}\n"
                )
            }
        )
        self.assertIn(("IAC-TF-007", 2), rules)

    def test_tfvars_analyzed(self) -> None:
        rules = _rules({"terraform/terraform.tfvars": 'db_password = "hunter2hunter2"\n'})
        self.assertIn(("IAC-TF-007", 1), rules)

    def test_placeholder_not_flagged(self) -> None:
        rules = _rules({"terraform/main.tf": 'variable "db_password" {\n  default = "changeme"\n}\n'})
        self.assertEqual(rules, set())


class GitLabCiRuleTests(unittest.TestCase):
    def test_remote_include(self) -> None:
        rules = _rules(
            {".gitlab-ci.yml": "include:\n  - remote: https://example.com/ci/templates.yml\n"}
        )
        self.assertIn(("IAC-GITLAB-001", 2), rules)

    def test_project_include_mutable_ref(self) -> None:
        rules = _rules(
            {
                ".gitlab-ci.yml": (
                    "include:\n"
                    "  - project: acme/pipelines\n"
                    "    ref: main\n"
                )
            }
        )
        self.assertIn(("IAC-GITLAB-004", 3), rules)

    def test_piped_shell_in_script(self) -> None:
        rules = _rules(
            {
                ".gitlab-ci.yml": (
                    "build:\n"
                    "  script:\n"
                    "    - curl -sSL https://example.com/install.sh | sh\n"
                )
            }
        )
        self.assertIn(("IAC-GITLAB-002", 2), rules)

    def test_hardcoded_variable_secret(self) -> None:
        rules = _rules(
            {
                ".gitlab-ci.yml": (
                    "build:\n"
                    "  variables:\n"
                    "    DEPLOY_TOKEN: literal_secret_value\n"
                    "    DEPLOY_MODE: fast\n"
                    "deploy:\n"
                    "  script: echo done\n"
                )
            }
        )
        self.assertIn(("IAC-GITLAB-003", 3), rules)
        self.assertEqual(
            len([rule for rule, _ in rules if rule == "IAC-GITLAB-003"]),
            1,
        )

    def test_benign_pipeline(self) -> None:
        rules = _rules(
            {
                ".gitlab-ci.yml": (
                    "stages:\n"
                    "  - build\n"
                    "build:\n"
                    "  stage: build\n"
                    "  script:\n"
                    "    - make build\n"
                    "  variables:\n"
                    "    DEPLOY_TOKEN: $CI_DEPLOY_TOKEN\n"
                )
            }
        )
        self.assertEqual(rules, set())


class JenkinsfileRuleTests(unittest.TestCase):
    def test_piped_shell(self) -> None:
        rules = _rules({"Jenkinsfile": "pipeline {\n  steps {\n    sh 'curl -s https://x.example | sh'\n  }\n}\n"})
        self.assertIn(("IAC-JENKINS-001", 3), rules)

    def test_hardcoded_environment_secret(self) -> None:
        rules = _rules(
            {"Jenkinsfile": "pipeline {\n  environment {\n    DEPLOY_TOKEN = 'literal_secret_v'\n    MODE = 'fast'\n  }\n}\n"}
        )
        self.assertIn(("IAC-JENKINS-002", 3), rules)
        self.assertEqual(
            len([rule for rule, _ in rules if rule == "IAC-JENKINS-002"]),
            1,
        )

    def test_privileged_docker(self) -> None:
        rules = _rules({"Jenkinsfile": "sh 'docker run --privileged -it alpine sh'\n"})
        self.assertIn(("IAC-JENKINS-003", 1), rules)


class AnalyzerBehaviorTests(unittest.TestCase):
    def test_all_findings_carry_rule_ids(self) -> None:
        _, findings = _run(
            {
                "Dockerfile": "FROM python\n",
                ".github/workflows/ci.yml": "on: push\npermissions: write-all\n",
                "k8s/deployment.yaml": "kind: Pod\nspec:\n  containers:\n    - image: app:latest\n",
            }
        )
        self.assertTrue(findings)
        for finding in findings:
            self.assertRegex(str(finding.metadata.get("rule_id")), r"^IAC-[A-Z0-9]+-\d{3}$")

    def test_deterministic_output(self) -> None:
        files = {
            "Dockerfile": "FROM python\n",
            "docker-compose.yml": "services:\n  api:\n    image: app:latest\n    privileged: true\n",
        }
        first = _run(files)
        second = _run(files)
        self.assertEqual(
            [(f.id, f.metadata["rule_id"], f.evidence[0].line) for f in first[1]],
            [(f.id, f.metadata["rule_id"], f.evidence[0].line) for f in second[1]],
        )
        self.assertEqual(
            sorted(n.id for n in first[0].nodes.values()),
            sorted(n.id for n in second[0].nodes.values()),
        )

    def test_path_escape_is_skipped(self) -> None:
        _, findings = _run({"Dockerfile": "FROM python\n"})
        self.assertEqual(findings[0].metadata["rule_id"], "IAC-DOCKER-001")
        from secdiagram_core import iac

        repo = RepoInfo(root=Path.cwd(), name="repo", rel_files=[])
        result = iac._dockerfile(repo.root, "../outside/Dockerfile")
        self.assertEqual(result.findings, [])
        self.assertEqual(result.nodes, [])


if __name__ == "__main__":
    unittest.main()
