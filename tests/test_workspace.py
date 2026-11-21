"""Tests for the multi-repo workspace analysis feature."""

from __future__ import annotations

import json
import textwrap
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from secdiagram_core.model import Graph, Loc, Node
from secdiagram_core.workspace import (
    VALID_ROLES,
    InterRepoEdge,
    RepoRole,
    Workspace,
    _detect_inter_repo_edges,
    _detect_role_from_directory_name,
    _detect_role_from_package_json,
    _detect_role_from_python,
    _load_workspace_config,
    detect_repo_role,
    discover_workspace,
    merge_graphs,
)


class TestRepoRoleSerialization(unittest.TestCase):
    def test_round_trip(self):
        role = RepoRole(
            path=Path("/tmp/my-repo"),
            name="my-repo",
            role="backend",
            confidence=0.9,
            evidence=["Python dep: FastAPI"],
            manual=False,
        )
        data = role.to_dict()
        restored = RepoRole.from_dict(data)
        self.assertEqual(restored.name, "my-repo")
        self.assertEqual(restored.role, "backend")
        self.assertAlmostEqual(restored.confidence, 0.9, places=2)
        self.assertEqual(restored.evidence, ["Python dep: FastAPI"])
        self.assertFalse(restored.manual)

    def test_manual_role(self):
        role = RepoRole(
            path=Path("/tmp/svc"),
            name="svc",
            role="gateway",
            manual=True,
            evidence=["manual override: gateway"],
        )
        self.assertTrue(role.manual)
        data = role.to_dict()
        self.assertTrue(data["manual"])


class TestInterRepoEdgeSerialization(unittest.TestCase):
    def test_round_trip(self):
        edge = InterRepoEdge(
            src_repo="api",
            dst_repo="user-service",
            kind="http",
            label="REST call",
            confidence=0.7,
            evidence=["api references user-service"],
        )
        data = edge.to_dict()
        restored = InterRepoEdge.from_dict(data)
        self.assertEqual(restored.src_repo, "api")
        self.assertEqual(restored.dst_repo, "user-service")
        self.assertEqual(restored.kind, "http")


class TestWorkspaceSerialization(unittest.TestCase):
    def test_round_trip(self):
        ws = Workspace(
            name="my-product",
            root=Path("/tmp/product"),
            repos=[
                RepoRole(Path("/tmp/product/api"), "api", "backend"),
                RepoRole(Path("/tmp/product/web"), "web", "frontend"),
            ],
            inter_repo_edges=[
                InterRepoEdge("web", "api", "http", "API calls"),
            ],
        )
        data = ws.to_dict()
        restored = Workspace.from_dict(data)
        self.assertEqual(restored.name, "my-product")
        self.assertEqual(len(restored.repos), 2)
        self.assertEqual(len(restored.inter_repo_edges), 1)


class TestValidRoles(unittest.TestCase):
    def test_all_expected_roles_present(self):
        expected = {
            "backend", "frontend", "gateway", "worker",
            "data-layer", "infrastructure", "library", "unknown",
        }
        self.assertEqual(VALID_ROLES, expected)


class TestDetectRoleFromPackageJson(unittest.TestCase):
    def test_frontend_react(self):
        with TemporaryDirectory() as tmp:
            (Path(tmp) / "package.json").write_text(json.dumps({
                "name": "web-app",
                "dependencies": {"react": "^18.0", "react-dom": "^18.0"},
            }))
            role, conf, evidence = _detect_role_from_package_json(Path(tmp))
            self.assertEqual(role, "frontend")
            self.assertGreater(conf, 0.5)

    def test_backend_express(self):
        with TemporaryDirectory() as tmp:
            (Path(tmp) / "package.json").write_text(json.dumps({
                "name": "api-server",
                "dependencies": {"express": "^4.18"},
            }))
            role, conf, evidence = _detect_role_from_package_json(Path(tmp))
            self.assertEqual(role, "backend")
            self.assertGreater(conf, 0.5)

    def test_nextjs_as_frontend(self):
        with TemporaryDirectory() as tmp:
            (Path(tmp) / "package.json").write_text(json.dumps({
                "name": "frontend",
                "dependencies": {"next": "^14.0", "react": "^18.0"},
            }))
            role, conf, evidence = _detect_role_from_package_json(Path(tmp))
            self.assertEqual(role, "frontend")

    def test_no_package_json(self):
        with TemporaryDirectory() as tmp:
            role, conf, evidence = _detect_role_from_package_json(Path(tmp))
            self.assertEqual(role, "unknown")
            self.assertEqual(conf, 0.0)

    def test_worker_bullmq(self):
        with TemporaryDirectory() as tmp:
            (Path(tmp) / "package.json").write_text(json.dumps({
                "name": "queue-worker",
                "dependencies": {"bullmq": "^4.0"},
            }))
            role, conf, evidence = _detect_role_from_package_json(Path(tmp))
            self.assertEqual(role, "worker")


class TestDetectRoleFromPython(unittest.TestCase):
    def test_fastapi_backend(self):
        with TemporaryDirectory() as tmp:
            (Path(tmp) / "pyproject.toml").write_text(textwrap.dedent("""\
                [project]
                name = "my-api"
                dependencies = ["fastapi", "uvicorn"]
            """))
            role, conf, evidence = _detect_role_from_python(Path(tmp))
            self.assertEqual(role, "backend")
            self.assertGreater(conf, 0.5)

    def test_celery_worker(self):
        with TemporaryDirectory() as tmp:
            (Path(tmp) / "pyproject.toml").write_text(textwrap.dedent("""\
                [project]
                name = "task-worker"
                dependencies = ["celery"]
            """))
            role, conf, evidence = _detect_role_from_python(Path(tmp))
            self.assertEqual(role, "worker")

    def test_data_layer_pandas(self):
        with TemporaryDirectory() as tmp:
            (Path(tmp) / "pyproject.toml").write_text(textwrap.dedent("""\
                [project]
                name = "data-processor"
                dependencies = ["pandas", "numpy"]
            """))
            role, conf, evidence = _detect_role_from_python(Path(tmp))
            self.assertEqual(role, "data-layer")

    def test_library_pattern(self):
        with TemporaryDirectory() as tmp:
            (Path(tmp) / "setup.py").write_text("from setuptools import setup; setup(name='mylib')")
            role, conf, evidence = _detect_role_from_python(Path(tmp))
            self.assertEqual(role, "library")

    def test_no_python_project(self):
        with TemporaryDirectory() as tmp:
            role, conf, evidence = _detect_role_from_python(Path(tmp))
            self.assertEqual(role, "unknown")


class TestDetectRoleFromDirectoryName(unittest.TestCase):
    def test_directory_role_matrix_keeps_evidence_and_gateway_precedence(self):
        for name, expected in (
            ("my-frontend-app", "frontend"),
            ("user-service-api", "backend"),
            ("api-gateway", "gateway"),
            ("API_GATEWAY", "gateway"),
            ("email-worker", "worker"),
            ("database", "data-layer"),
            ("infrastructure", "infrastructure"),
            ("shared-utils", "library"),
            ("xyz123", "unknown"),
        ):
            with self.subTest(name=name):
                role, confidence, evidence = _detect_role_from_directory_name(name)
                self.assertEqual(role, expected)
                self.assertEqual(confidence, 0.0 if expected == "unknown" else 0.4)
                self.assertEqual(
                    evidence,
                    []
                    if expected == "unknown"
                    else [f"directory name matches '{expected}' pattern"],
                )


class TestDetectRepoRole(unittest.TestCase):
    def test_manual_override(self):
        with TemporaryDirectory() as tmp:
            role = detect_repo_role(Path(tmp), manual_role="gateway")
            self.assertEqual(role.role, "gateway")
            self.assertTrue(role.manual)
            self.assertEqual(role.confidence, 1.0)

    def test_invalid_manual_role(self):
        with TemporaryDirectory() as tmp:
            role = detect_repo_role(Path(tmp), manual_role="invalid-role")
            self.assertEqual(role.role, "unknown")
            self.assertTrue(role.manual)

    def test_auto_detect_from_package_json(self):
        with TemporaryDirectory() as tmp:
            (Path(tmp) / "package.json").write_text(json.dumps({
                "name": "my-api",
                "dependencies": {"express": "^4.18"},
            }))
            role = detect_repo_role(Path(tmp))
            self.assertEqual(role.role, "backend")
            self.assertFalse(role.manual)

    def test_fallback_to_directory_name(self):
        with TemporaryDirectory(prefix="api-gateway-") as tmp:
            # tmp name is something like /tmp/api-gateway-xxxxx but we
            # won't match because the full path includes random suffix.
            # Instead test with a known subdir.
            d = Path(tmp) / "api-gateway"
            d.mkdir()
            role = detect_repo_role(d)
            self.assertEqual(role.role, "gateway")

    def test_infra_terraform(self):
        with TemporaryDirectory() as tmp:
            (Path(tmp) / "main.tf").write_text('resource "aws_instance" "web" {}')
            role = detect_repo_role(Path(tmp))
            self.assertEqual(role.role, "infrastructure")


class TestLoadWorkspaceConfig(unittest.TestCase):
    def test_load_config(self):
        with TemporaryDirectory() as tmp:
            config = {
                "name": "my-product",
                "repos": [
                    {"name": "api", "role": "backend"},
                    {"name": "web", "role": "frontend"},
                ],
            }
            (Path(tmp) / "workspace.json").write_text(json.dumps(config))
            loaded = _load_workspace_config(Path(tmp))
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded["name"], "my-product")
            self.assertEqual(len(loaded["repos"]), 2)

    def test_no_config(self):
        with TemporaryDirectory() as tmp:
            loaded = _load_workspace_config(Path(tmp))
            self.assertIsNone(loaded)

    def test_alternative_config_name(self):
        with TemporaryDirectory() as tmp:
            config = {"name": "alt-product"}
            (Path(tmp) / "secdiagram-workspace.json").write_text(json.dumps(config))
            loaded = _load_workspace_config(Path(tmp))
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded["name"], "alt-product")

    def test_malformed_json(self):
        with TemporaryDirectory() as tmp:
            (Path(tmp) / "workspace.json").write_text("not valid json {{{")
            loaded = _load_workspace_config(Path(tmp))
            self.assertIsNone(loaded)


class TestDiscoverWorkspace(unittest.TestCase):
    def _make_workspace(self, tmp: str) -> Path:
        root = Path(tmp)
        # Create backend repo
        backend = root / "user-service"
        backend.mkdir()
        (backend / "pyproject.toml").write_text(textwrap.dedent("""\
            [project]
            name = "user-service"
            dependencies = ["fastapi"]
        """))
        (backend / "main.py").write_text("from fastapi import FastAPI\napp = FastAPI()")

        # Create frontend repo
        frontend = root / "web-app"
        frontend.mkdir()
        (frontend / "package.json").write_text(json.dumps({
            "name": "web-app",
            "dependencies": {"react": "^18.0", "react-dom": "^18.0"},
        }))
        (frontend / "index.tsx").write_text("import React from 'react';")

        # Create infrastructure repo
        infra = root / "infra"
        infra.mkdir()
        (infra / "main.tf").write_text('resource "aws_vpc" "main" {}')

        return root

    def test_discover_repos(self):
        with TemporaryDirectory() as tmp:
            root = self._make_workspace(tmp)
            ws = discover_workspace(root)
            self.assertGreaterEqual(len(ws.repos), 2)
            names = {r.name for r in ws.repos}
            self.assertIn("user-service", names)
            self.assertIn("web-app", names)

    def test_auto_detect_roles(self):
        with TemporaryDirectory() as tmp:
            root = self._make_workspace(tmp)
            ws = discover_workspace(root)
            roles = {r.name: r.role for r in ws.repos}
            self.assertEqual(roles.get("user-service"), "backend")
            self.assertEqual(roles.get("web-app"), "frontend")
            self.assertEqual(roles.get("infra"), "infrastructure")

    def test_manual_role_override(self):
        with TemporaryDirectory() as tmp:
            root = self._make_workspace(tmp)
            ws = discover_workspace(root, manual_roles={"user-service": "gateway"})
            roles = {r.name: r for r in ws.repos}
            self.assertEqual(roles["user-service"].role, "gateway")
            self.assertTrue(roles["user-service"].manual)
            # Other repos still auto-detected
            self.assertEqual(roles["web-app"].role, "frontend")

    def test_workspace_config_roles(self):
        with TemporaryDirectory() as tmp:
            root = self._make_workspace(tmp)
            config = {
                "name": "my-product",
                "repos": [
                    {"name": "user-service", "role": "worker"},
                ],
            }
            (root / "workspace.json").write_text(json.dumps(config))
            ws = discover_workspace(root)
            roles = {r.name: r for r in ws.repos}
            # workspace.json should override auto-detect
            self.assertEqual(roles["user-service"].role, "worker")
            self.assertTrue(roles["user-service"].manual)
            self.assertEqual(ws.name, "my-product")

    def test_manual_roles_take_precedence_over_config(self):
        with TemporaryDirectory() as tmp:
            root = self._make_workspace(tmp)
            config = {
                "name": "product",
                "repos": [
                    {"name": "user-service", "role": "worker"},
                ],
            }
            (root / "workspace.json").write_text(json.dumps(config))
            # CLI manual_roles should beat workspace.json
            ws = discover_workspace(root, manual_roles={"user-service": "gateway"})
            roles = {r.name: r for r in ws.repos}
            self.assertEqual(roles["user-service"].role, "gateway")

    def test_explicit_repo_paths(self):
        with TemporaryDirectory() as tmp:
            root = self._make_workspace(tmp)
            ws = discover_workspace(
                root,
                repo_paths=[str(root / "user-service")],
            )
            self.assertEqual(len(ws.repos), 1)
            self.assertEqual(ws.repos[0].name, "user-service")

    def test_nonexistent_root_raises(self):
        with self.assertRaises(FileNotFoundError):
            discover_workspace("/nonexistent/path/that/does/not/exist")

    def test_skips_hidden_dirs(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            hidden = root / ".hidden"
            hidden.mkdir()
            (hidden / "package.json").write_text("{}")
            ws = discover_workspace(root)
            names = {r.name for r in ws.repos}
            self.assertNotIn(".hidden", names)


class TestInterRepoEdgeDetection(unittest.TestCase):
    def test_frontend_to_backend_inference(self):
        repos = [
            RepoRole(Path("/tmp/web"), "web", "frontend"),
            RepoRole(Path("/tmp/api"), "api", "backend"),
        ]
        from secdiagram_core.discover import RepoInfo

        infos = {
            "web": RepoInfo(root=Path("/tmp/web"), name="web", rel_files=[]),
            "api": RepoInfo(root=Path("/tmp/api"), name="api", rel_files=[]),
        }
        edges = _detect_inter_repo_edges(repos, infos)
        # Should infer frontendâ†’backend edge
        http_edges = [e for e in edges if e.kind == "http"]
        self.assertGreater(len(http_edges), 0)
        self.assertEqual(http_edges[0].src_repo, "web")
        self.assertEqual(http_edges[0].dst_repo, "api")

    def test_gateway_to_backend_inference(self):
        repos = [
            RepoRole(Path("/tmp/gw"), "gw", "gateway"),
            RepoRole(Path("/tmp/users"), "users", "backend"),
        ]
        from secdiagram_core.discover import RepoInfo

        infos = {
            "gw": RepoInfo(root=Path("/tmp/gw"), name="gw", rel_files=[]),
            "users": RepoInfo(root=Path("/tmp/users"), name="users", rel_files=[]),
        }
        edges = _detect_inter_repo_edges(repos, infos)
        gw_edges = [e for e in edges if e.src_repo == "gw"]
        self.assertGreater(len(gw_edges), 0)

    def test_no_self_edges(self):
        repos = [
            RepoRole(Path("/tmp/api"), "api", "backend"),
        ]
        from secdiagram_core.discover import RepoInfo

        infos = {
            "api": RepoInfo(root=Path("/tmp/api"), name="api", rel_files=[]),
        }
        edges = _detect_inter_repo_edges(repos, infos)
        self.assertEqual(edges, [], "a single unreferenced repository must not create inferred edges")


class TestMergeGraphs(unittest.TestCase):
    def test_basic_merge(self):
        g1 = Graph()
        n1 = Node(id="n1", kind="class", name="User", qualname="app.User", path="models.py", line=10)
        g1.add_node(n1)

        g2 = Graph()
        n2 = Node(id="n2", kind="class", name="Order", qualname="app.Order", path="models.py", line=5)
        g2.add_node(n2)

        roles = {
            "api": RepoRole(Path("/tmp/api"), "api", "backend"),
            "orders": RepoRole(Path("/tmp/orders"), "orders", "backend"),
        }

        merged = merge_graphs({"api": g1, "orders": g2}, roles, [])
        self.assertEqual(len(merged.nodes), 2)

        # Nodes should have workspace_repo attr
        for node in merged.nodes.values():
            self.assertIn("workspace_repo", node.attrs)
            self.assertIn(node.attrs["workspace_repo"], {"api", "orders"})

    def test_path_prefixing(self):
        g1 = Graph()
        n1 = Node(id="n1", kind="module", name="app", qualname="app", path="app.py", line=1)
        g1.add_node(n1)

        roles = {"svc": RepoRole(Path("/tmp/svc"), "svc", "backend")}
        merged = merge_graphs({"svc": g1}, roles, [])

        node = list(merged.nodes.values())[0]
        self.assertTrue(node.path.startswith("svc/"))

    def test_qualname_prefixing(self):
        g1 = Graph()
        n1 = Node(id="n1", kind="class", name="Foo", qualname="mod.Foo")
        g1.add_node(n1)

        roles = {"repo1": RepoRole(Path("/tmp/r"), "repo1", "backend")}
        merged = merge_graphs({"repo1": g1}, roles, [])

        node = list(merged.nodes.values())[0]
        self.assertTrue(node.qualname.startswith("repo1::"))

    def test_edges_remapped(self):
        g1 = Graph()
        g1.add_node(Node(id="a", kind="function", name="f", qualname="f"))
        g1.add_node(Node(id="b", kind="function", name="g", qualname="g"))
        g1.add_edge("a", "b", "calls")

        roles = {"r": RepoRole(Path("/tmp/r"), "r", "backend")}
        merged = merge_graphs({"r": g1}, roles, [])

        self.assertEqual(len(merged.edges), 1)
        edge = merged.edges[0]
        # Edge src/dst should be remapped IDs, not originals
        self.assertNotEqual(edge.src, "a")
        self.assertNotEqual(edge.dst, "b")
        self.assertIn(edge.src, merged.nodes)
        self.assertIn(edge.dst, merged.nodes)

    def test_cross_repo_edges(self):
        g1 = Graph()
        g1.add_node(Node(id="ep1", kind="endpoint", name="/api/users", qualname="/api/users"))
        g2 = Graph()
        g2.add_node(Node(id="ep2", kind="endpoint", name="/orders", qualname="/orders"))

        roles = {
            "api": RepoRole(Path("/tmp/api"), "api", "backend"),
            "orders": RepoRole(Path("/tmp/orders"), "orders", "backend"),
        }
        inter_edges = [
            InterRepoEdge("api", "orders", "http", "API call"),
        ]
        merged = merge_graphs({"api": g1, "orders": g2}, roles, inter_edges)

        cross_edges = [e for e in merged.edges if e.kind.startswith("cross-repo-")]
        self.assertEqual(len(cross_edges), 1)
        self.assertEqual(cross_edges[0].kind, "cross-repo-http")
        self.assertTrue(cross_edges[0].attrs.get("cross_repo"))

    def test_findings_remapped(self):
        g1 = Graph()
        n1 = Node(id="n1", kind="function", name="unsafe", qualname="unsafe", path="views.py", line=10)
        g1.add_node(n1)
        from secdiagram_core.model import Finding

        g1.findings.append(Finding(
            id="f1",
            category="sql-injection",
            severity="high",
            title="SQL Injection",
            message="Unsafe query",
            node_id="n1",
            evidence=[Loc("views.py", 10)],
        ))

        roles = {"svc": RepoRole(Path("/tmp/svc"), "svc", "backend")}
        merged = merge_graphs({"svc": g1}, roles, [])

        self.assertEqual(len(merged.findings), 1)
        finding = merged.findings[0]
        self.assertTrue(finding.title.startswith("[svc]"))
        self.assertEqual(finding.metadata.get("workspace_repo"), "svc")
        self.assertTrue(finding.evidence[0].path.startswith("svc/"))

    def test_deterministic_ids(self):
        """Same input produces same node IDs (determinism requirement)."""
        g1 = Graph()
        g1.add_node(Node(id="x", kind="class", name="A", qualname="A"))

        roles = {"r": RepoRole(Path("/tmp/r"), "r", "backend")}
        m1 = merge_graphs({"r": g1}, roles, [])
        m2 = merge_graphs({"r": g1}, roles, [])

        ids1 = sorted(m1.nodes.keys())
        ids2 = sorted(m2.nodes.keys())
        self.assertEqual(ids1, ids2)


class TestWorkspaceEndToEnd(unittest.TestCase):
    """Integration test: create a micro workspace and analyze it."""

    def test_workspace_analysis(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)

            # Backend repo
            backend = root / "api"
            backend.mkdir()
            (backend / "pyproject.toml").write_text(textwrap.dedent("""\
                [project]
                name = "api"
                dependencies = ["fastapi"]
            """))
            (backend / "main.py").write_text(textwrap.dedent("""\
                from fastapi import FastAPI
                app = FastAPI()

                @app.get("/users")
                def get_users():
                    return []
            """))

            # Frontend repo
            frontend = root / "web"
            frontend.mkdir()
            (frontend / "package.json").write_text(json.dumps({
                "name": "web",
                "dependencies": {"react": "^18.0", "react-dom": "^18.0"},
            }))
            (frontend / "App.tsx").write_text("export const App = () => <div>Hello</div>;")

            from secdiagram_core.analyzer import run_workspace_analysis

            result = run_workspace_analysis(root)

            self.assertEqual(result.workspace.name, root.name)
            self.assertGreaterEqual(len(result.workspace.repos), 2)
            self.assertGreater(len(result.merged_graph.nodes), 0)

            # Check roles detected
            roles = {r.name: r.role for r in result.workspace.repos}
            self.assertEqual(roles.get("api"), "backend")
            self.assertEqual(roles.get("web"), "frontend")


class TestCLIWorkspaceArgs(unittest.TestCase):
    def test_parse_role_args(self):
        from secdiagram_core.cli import _parse_role_args

        roles = _parse_role_args([
            "user-service=backend",
            "web-app=frontend",
            "api-gw=gateway",
        ])
        self.assertEqual(roles, {
            "user-service": "backend",
            "web-app": "frontend",
            "api-gw": "gateway",
        })

    def test_parse_role_args_empty(self):
        from secdiagram_core.cli import _parse_role_args

        self.assertEqual(_parse_role_args([]), {})

    def test_parse_role_args_invalid(self):
        from secdiagram_core.cli import _parse_role_args

        # Items without = are skipped
        roles = _parse_role_args(["noequalssign"])
        self.assertEqual(roles, {})

    def test_parser_accepts_workspace_flag(self):
        from secdiagram_core.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(["--workspace", "/some/path"])
        self.assertEqual(args.workspace, "/some/path")

    def test_parser_accepts_role_flag(self):
        from secdiagram_core.cli import build_parser

        parser = build_parser()
        args = parser.parse_args([
            "--workspace", "/path",
            "--role", "api=backend",
            "--role", "web=frontend",
        ])
        self.assertEqual(args.role, ["api=backend", "web=frontend"])


class TestMergeGraphsDeterminism(unittest.TestCase):
    """Verify that merging is deterministic (Rule 2 of AGENTS.md)."""

    def test_sorted_output(self):
        g1 = Graph()
        g1.add_node(Node(id="b", kind="class", name="B", qualname="B"))
        g1.add_node(Node(id="a", kind="class", name="A", qualname="A"))

        g2 = Graph()
        g2.add_node(Node(id="c", kind="class", name="C", qualname="C"))

        roles = {
            "r1": RepoRole(Path("/tmp/r1"), "r1", "backend"),
            "r2": RepoRole(Path("/tmp/r2"), "r2", "frontend"),
        }

        m1 = merge_graphs({"r1": g1, "r2": g2}, roles, [])
        m2 = merge_graphs({"r2": g2, "r1": g1}, roles, [])

        # Regardless of input dict order, same nodes should appear
        self.assertEqual(sorted(m1.nodes.keys()), sorted(m2.nodes.keys()))
        self.assertEqual(m1.to_dict(), m2.to_dict(), "node IDs alone do not prove deterministic graph content")

    def test_feature_prefixed_with_repo_name(self):
        g1 = Graph()
        g1.add_node(Node(
            id="n1", kind="class", name="X", qualname="X",
            feature="auth",
        ))

        roles = {"svc": RepoRole(Path("/tmp/svc"), "svc", "backend")}
        merged = merge_graphs({"svc": g1}, roles, [])
        node = list(merged.nodes.values())[0]
        self.assertEqual(node.feature, "svc/auth")


class TestDetectRoleFromInfra(unittest.TestCase):
    def test_helm_chart(self):
        with TemporaryDirectory() as tmp:
            (Path(tmp) / "Chart.yaml").write_text("apiVersion: v2\nname: myapp")
            role = detect_repo_role(Path(tmp))
            self.assertEqual(role.role, "infrastructure")

    def test_k8s_manifests(self):
        with TemporaryDirectory() as tmp:
            k8s = Path(tmp) / "k8s"
            k8s.mkdir()
            (k8s / "deployment.yaml").write_text("apiVersion: apps/v1\nkind: Deployment")
            role = detect_repo_role(Path(tmp))
            self.assertEqual(role.role, "infrastructure")


class TestBridgeNodesForCrossRepoEdges(unittest.TestCase):
    """When repos have no endpoints, synthetic bridge nodes should be created."""

    def test_bridge_nodes_created(self):
        g1 = Graph()
        g1.add_node(Node(id="c1", kind="class", name="Foo", qualname="Foo"))
        g2 = Graph()
        g2.add_node(Node(id="c2", kind="class", name="Bar", qualname="Bar"))

        roles = {
            "a": RepoRole(Path("/tmp/a"), "a", "backend"),
            "b": RepoRole(Path("/tmp/b"), "b", "backend"),
        }
        edges = [InterRepoEdge("a", "b", "http", "call")]
        merged = merge_graphs({"a": g1, "b": g2}, roles, edges)

        # Should have bridge nodes for cross-repo edges
        bridge_nodes = [n for n in merged.nodes.values() if n.attrs.get("bridge")]
        self.assertGreater(len(bridge_nodes), 0)

        # Should have a cross-repo edge
        cross_edges = [e for e in merged.edges if e.kind.startswith("cross-repo-")]
        self.assertEqual(len(cross_edges), 1)


if __name__ == "__main__":
    unittest.main()
