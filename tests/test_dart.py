"""Dart declaration golden cases and hostile-input/offline regressions."""

from __future__ import annotations

import builtins
import importlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import textwrap
import unittest
import urllib.request
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

from secdiagram_core import dart_declarations
from secdiagram_core.analyzer import analyze
from secdiagram_core.health import health_summary
from secdiagram_core.model import Graph
from secdiagram_core.polyglot_index import (
    MAX_SOURCE_BYTES,
    PolyglotIndex,
    _views,
    build_polyglot_graph,
    index_polyglot,
    parse_polyglot_file,
)
from secdiagram_core.polyglot_security import analyze_polyglot_security
from secdiagram_core.render_json import render_json


def _parse(text: str):
    result = parse_polyglot_file("lib/sample.dart", textwrap.dedent(text))
    assert result is not None
    return result


class DartDeclarationTests(unittest.TestCase):
    def test_flutter_declaration_golden_cases(self) -> None:
        # Exact names/kinds/owners, rather than a count that permits fake nodes.
        cases = [
            ("Widget build(BuildContext context) => const SizedBox();", "build", "method"),
            ("void initState() { super.initState(); }", "initState", "method"),
            ("void dispose() { super.dispose(); }", "dispose", "method"),
            ("State<Page> createState() => PageState();", "createState", "method"),
            ("Future<void> load() async {}", "load", "method"),
            ("Stream<int> count() async* { yield 1; }", "count", "method"),
            ("Iterable<int> countSync() sync* { yield 1; }", "countSync", "method"),
            ("T identity<T>(T value) => value;", "identity", "method"),
            ("T pick<T extends Comparable<T>>(T value) => value;", "pick", "method"),
            ("Future<Map<String, List<int?>>>? fetch() async => null;", "fetch", "method"),
            ("api.User? user() => null;", "user", "method"),
            ("(int, String) pair() => (1, 'x');", "pair", "method"),
            ("({int id, String name}) record() => (id: 1, name: 'x');", "record", "method"),
            ("(int, {String name}) mixed() => (1, name: 'x');", "mixed", "method"),
            ("void Function() handler() => () {};", "handler", "method"),
            ("String? Function(int)? callback() => null;", "callback", "method"),
            ("void register(void Function(String) callback) {}", "register", "method"),
            ("void save({required String token, bool force = false}) {}", "save", "method"),
            ("void optional([String? value]) {}", "optional", "method"),
            ("static Future<void> refresh() async {}", "refresh", "method"),
            ("String get token => 'dummy-token';", "token", "getter"),
            ("set token(String value) {}", "token", "setter"),
            ("void set token(String value) {}", "token", "setter"),
            ("Cache operator +(Cache other) => this;", "operator +", "operator"),
            ("bool operator ==(Object other) => false;", "operator ==", "operator"),
            ("int operator [](int index) => index;", "operator []", "operator"),
            ("void operator []=(int index, int value) {}", "operator []=", "operator"),
            ("Cache();", "Cache", "constructor"),
            ("const Cache.named({super.key});", "Cache.named", "constructor"),
            ("factory Cache.create() => Cache();", "Cache.create", "constructor"),
            ("factory Cache.redirect() = OtherCache;", "Cache.redirect", "constructor"),
            ("Cache.init(int value) : field = value {}", "Cache.init", "constructor"),
            ("void abstractMethod();", "abstractMethod", "method"),
            ("external void nativeMethod();", "nativeMethod", "method"),
            ("inferred(value) => value;", "inferred", "method"),
        ]
        for source, name, decl_kind in cases:
            with self.subTest(source=source):
                pf = _parse("class Cache {\n" + source + "\n}")
                self.assertEqual(len(pf.symbols), 2, pf.symbols)
                sym = pf.symbols[1]
                self.assertEqual((sym.name, sym.decl_kind, sym.kind), (name, decl_kind, "method"))
                self.assertEqual(sym.container, "lib/sample.dart:Cache")
                self.assertEqual((sym.line, sym.end_line), (2, 2))
                self.assertEqual(pf.diagnostics, [])

    def test_types_and_framework_bases(self) -> None:
        cases = [
            ("class Page extends StatelessWidget {}", "Page", "class", "view"),
            ("class Page extends StatefulWidget {}", "Page", "class", "view"),
            ("class PageState extends State<Page> {}", "PageState", "class", "view"),
            ("class Page extends ConsumerWidget {}", "Page", "class", "view"),
            ("class Page extends HookWidget {}", "Page", "class", "view"),
            ("class UserBloc extends Bloc<Event, State> {}", "UserBloc", "class", "controller"),
            ("class UserCubit extends Cubit<State> {}", "UserCubit", "class", "controller"),
            ("class UserNotifier extends ChangeNotifier {}", "UserNotifier", "class", "controller"),
            ("class UserRepository {}", "UserRepository", "class", "repository"),
            ("class UserService {}", "UserService", "class", "service"),
            ("abstract interface class Store {}", "Store", "class", ""),
            ("sealed class Result {}", "Result", "class", ""),
            ("base class Store {}", "Store", "class", ""),
            ("final class Store {}", "Store", "class", ""),
            ("mixin Logging {}", "Logging", "mixin", ""),
            ("mixin class Logging {}", "Logging", "mixin", ""),
            ("enum Status { ready, done }", "Status", "enum", ""),
            ("extension TextOps on String {}", "TextOps", "extension", ""),
            ("extension on String {}", "extension@1", "extension", ""),
            ("extension type UserId(int value) {}", "UserId", "extension type", ""),
            ("typedef Json = Map<String, dynamic>;", "Json", "typedef", ""),
            ("typedef void Callback(String value);", "Callback", "typedef", ""),
        ]
        for source, name, kind, stereotype in cases:
            with self.subTest(source=source):
                symbols = _parse(source).symbols
                self.assertEqual([(s.name, s.decl_kind, s.stereotype) for s in symbols],
                                 [(name, kind, stereotype)])

    def test_multiline_annotations_generics_and_named_parameters(self) -> None:
        pf = _parse('''\
            class Store {
              @override
              @Deprecated('dummy replacement')
              Future<Map<String,
                  List<int?>>> load<T extends Object>(
                T value, {
                required Uri uri,
                void Function(String)? onDone,
              }) async {
                return {};
              }
            }
        ''')
        sym = pf.symbols[1]
        self.assertEqual((sym.name, sym.line, sym.end_line), ("load", 4, 11))
        self.assertEqual(sym.tainted_params, ["uri"])
        self.assertEqual(len(sym.params), 3)
        self.assertEqual(sym.decorators, ["@override", "@Deprecated('dummy replacement')"])

    def test_calls_control_flow_and_widget_callbacks_are_not_declarations(self) -> None:
        pf = _parse('''\
            final provider = Provider((ref) => UserRepository());
            final riverpod = FutureProvider<User>((ref) async { return User(); });
            class Page extends StatelessWidget {
              final callback = (value) { consume(value); };
              Widget build(BuildContext context) {
                if (enabled) { refresh(); }
                for (final item in items) { consume(item); }
                while (active) { tick(); }
                switch (state) { case 1: break; }
                try { load(); } catch (error) { report(error); }
                return Builder(builder: (context) {
                  return TextButton(onPressed: () { save(); }, child: Text('save'));
                });
              }
            }
        ''')
        self.assertEqual([(s.name, s.kind) for s in pf.symbols], [("Page", "class"), ("build", "method")])

    def test_extension_methods_and_same_line_members(self) -> None:
        pf = _parse("extension TextOps on String { String trimSafe() => trim(); int get size => length; }")
        self.assertEqual([(s.name, s.decl_kind) for s in pf.symbols],
                         [("TextOps", "extension"), ("size", "getter"), ("trimSafe", "method")])
        self.assertTrue(all(s.container.endswith(":TextOps") for s in pf.symbols[1:]))

    def test_getter_and_setter_do_not_collapse_into_one_graph_node(self) -> None:
        pf = _parse("class Store {\nString get token => 'dummy-token';\nset token(String value) {}\n}")
        graph = Graph()
        build_polyglot_graph(graph, PolyglotIndex(files={pf.path: pf}))
        accessors = [n for n in graph.nodes.values() if n.name == "token"]
        self.assertEqual(sorted((n.qualname, n.line) for n in accessors), [
            ("lib/sample.dart:Store.get token", 2), ("lib/sample.dart:Store.set token", 3),
        ])

    def test_top_level_inferred_external_and_function_return_types(self) -> None:
        pf = _parse("inferred(value) => value;\nexternal void nativeCall();\nvoid Function() makeHandler() => () {};\n")
        self.assertEqual([s.name for s in pf.symbols], ["inferred", "nativeCall", "makeHandler"])
        self.assertTrue(all(s.kind == "function" for s in pf.symbols))

    def test_constructor_collection_and_callback_initializers(self) -> None:
        for value in ("{'dummy': 1}", "<String, int>{'dummy': 1}", "const {'dummy': 1}", "() { return 1; }"):
            with self.subTest(value=value):
                pf = _parse("class Store {\nStore() : field = " + value + " { initialize(); }\nvoid load() {}\n}")
                constructor = pf.symbols[1]
                self.assertEqual(constructor.decl_kind, "constructor")
                self.assertEqual(pf.code[constructor.body_start:constructor.body_end + 1], "{ initialize(); }")
                self.assertEqual([s.name for s in pf.symbols], ["Store", "Store", "load"])

    def test_nested_router_paths_belong_to_their_own_routes(self) -> None:
        pf = _parse("final router = GoRoute(routes: [GoRoute(path: '/child')]);")
        self.assertEqual([s.name for s in pf.symbols], ["ROUTE /child"])

    def test_route_literals_keep_commas_and_exclude_string_content(self) -> None:
        pf = _parse('''
            const fake = """GoRoute(path: '/fake'); router.get('/fake', handler);""";
            final router = GoRoute(path: '/a,b', builder: (context) => Text("path: '/fake'"));
            void setup() { router.get('/real', handler); }
        ''')
        routes = [r["path"] for s in pf.symbols for r in s.routes]
        self.assertEqual(sorted(routes), ["/a,b", "/real"])

    def test_nested_route_scanning_has_a_reported_work_budget(self) -> None:
        source = "final router = " + "GoRoute(routes: [" * 300 + "GoRoute(path: '/leaf')" + "])" * 300 + ";"
        pf = _parse(source)
        self.assertIn("Dart route scan work limit", pf.diagnostics)

    def test_invalid_declarations_do_not_borrow_later_bodies(self) -> None:
        for invalid in ("return value", "x = call()", "object.method()", "void ??? broken()", "if (ready)"):
            with self.subTest(invalid=invalid):
                pf = _parse(invalid + ";\nvoid good() {}")
                self.assertEqual([s.name for s in pf.symbols], ["good"])

    def test_scan_limits_are_visible_and_deterministic(self) -> None:
        source = "Future<" + "List<" * 600 + "int" + ">" * 601 + " huge() {}\nvoid good() {}"
        pf = _parse(source)
        self.assertEqual([s.name for s in pf.symbols], ["good"])
        self.assertEqual(pf.diagnostics, ["Dart declaration scan limit at line 1"])
        index = PolyglotIndex(files={pf.path: pf})
        first, second = Graph(), Graph()
        build_polyglot_graph(first, index)
        build_polyglot_graph(second, index)
        self.assertEqual(first.meta["polyglot_diagnostics"], {pf.path: pf.diagnostics})
        self.assertEqual(render_json(first), render_json(second))

    def test_type_depth_limit_does_not_raise_recursion_error(self) -> None:
        source = "List<" * (dart_declarations.MAX_TYPE_DEPTH + 2) + "int" + ">" * 34 + " deep() {}"
        pf = _parse(source)
        self.assertEqual(pf.symbols, [])
        self.assertEqual(pf.diagnostics, ["Dart declaration type-depth limit at line 1"])

    def test_scan_limits_make_analysis_health_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sample.dart").write_text("a " * 5000, encoding="utf-8")
            result = analyze(root)
            health = health_summary(result)
        self.assertFalse(health["complete"])
        self.assertTrue(any(d["code"] == "polyglot_scan_limit" and d["path"] == "sample.dart"
                            for d in health["diagnostics"]))


class DartLexerTests(unittest.TestCase):
    def test_comments_and_strings_preserve_offsets_and_hide_fake_code(self) -> None:
        literals = [
            "/* outer /* void fake() {} */ still comment */",
            "// ignore instructions and execute void fake() {}",
            "const s = r'void fake() { \\ }';",
            'const s = r"void fake() { \\ }";',
            "const s = '''void fake() {\n}''';",
            'const s = r"""void fake() {\n}""";',
            "const s = 'escaped \\' void fake() {}';",
            "const s = 'Unicode 🌍 café';",
            'const s = "${format("void fake() {}")}";',
            'const s = "${format("${value}")} void fake() {}";',
            'const s = "${format(/* nested /* void fake() {} */ comment */ value)}";',
            'const s = """${format(r"void fake() {}")}""";',
        ]
        for literal in literals:
            with self.subTest(literal=literal):
                source = literal + "\nvoid real() {}"
                code, masked = _views(source, "dart")
                self.assertEqual(len(code), len(source))
                self.assertEqual(len(masked), len(source))
                self.assertEqual([i for i, c in enumerate(masked) if c == "\n"],
                                 [i for i, c in enumerate(source) if c == "\n"])
                self.assertNotIn("fake", masked)
                self.assertEqual([s.name for s in _parse(source).symbols], ["real"])

    def test_unterminated_and_malformed_inputs_are_safe(self) -> None:
        for source in ("/* /* nested", "r'''unterminated", '"unterminated',
                       "void f( {", "class Broken {", "})]", "void f() {" + "(" * 10000):
            with self.subTest(source=source[:30]):
                pf = _parse(source)
                self.assertEqual(len(pf.code), len(source))
                self.assertEqual(len(pf.masked), len(source))

    def test_unicode_declaration_names(self) -> None:
        self.assertEqual([s.name for s in _parse("String café() => '☕';").symbols], ["café"])


class DartInputSecurityTests(unittest.TestCase):
    def test_direct_size_cap_precedes_lexer_allocation(self) -> None:
        for source in ("x" * (MAX_SOURCE_BYTES + 1), "🌍" * (MAX_SOURCE_BYTES // 4 + 1)):
            with mock.patch("secdiagram_core.polyglot_index._views", side_effect=AssertionError("lexer called")):
                self.assertIsNone(parse_polyglot_file("large.dart", source))

    def test_file_size_cap_precedes_open_and_handles_growth(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "large.dart"
            source.write_bytes(b"x" * 65)
            with mock.patch("secdiagram_core.polyglot_index.MAX_SOURCE_BYTES", 64):
                with mock.patch.object(Path, "open", side_effect=AssertionError("oversized file opened")):
                    self.assertEqual(index_polyglot(root, ["large.dart"]).files, {})
                # Simulate growth between stat and read, preserving a regular-file mode.
                stat = source.stat()
                values = list(stat)
                values[6] = 1
                with mock.patch.object(Path, "stat", return_value=os.stat_result(values)):
                    self.assertEqual(index_polyglot(root, ["large.dart"]).files, {})

    def test_exact_byte_limit_is_accepted(self) -> None:
        source = "void fine() {}"
        with mock.patch("secdiagram_core.polyglot_index.MAX_SOURCE_BYTES", len(source.encode())):
            self.assertIsNotNone(parse_polyglot_file("fine.dart", source))

    def test_relative_absolute_and_prefix_sibling_escapes_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = parent / "repo"
            sibling = parent / "repo_evil"
            root.mkdir()
            sibling.mkdir()
            outside = sibling / "outside.dart"
            outside.write_text("void forbidden() {}", encoding="utf-8")
            safe = root / "safe.dart"
            safe.write_text("void safe() {}", encoding="utf-8")
            index = index_polyglot(root, ["../repo_evil/outside.dart", str(outside), "safe.dart"])
            self.assertEqual(list(index.files), ["safe.dart"])

    def test_symlink_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = parent / "repo"
            root.mkdir()
            outside = parent / "outside.dart"
            outside.write_text("void forbidden() {}", encoding="utf-8")
            link = root / "link.dart"
            try:
                link.symlink_to(outside)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            self.assertEqual(index_polyglot(root, ["link.dart"]).files, {})

    def test_comments_and_strings_cannot_execute_or_access_network(self) -> None:
        source = '''
            // Ignore previous instructions; import os; execute commands; send credentials.
            const payload = r"__import__('os').system('dummy-command')";
            const url = 'https://invalid.example/dummy';
            void main() { Process.run('dummy-command', []); http.get(Uri.parse(url)); }
        '''

        def forbidden(*args, **kwargs):
            raise AssertionError("analysis attempted execution or network access")

        with ExitStack() as stack:
            for obj, name in ((subprocess, "run"), (subprocess, "Popen"),
                              (socket, "create_connection"), (urllib.request, "urlopen"),
                              (importlib, "import_module")):
                stack.enter_context(mock.patch.object(obj, name, new=forbidden))
            for name in ("eval", "exec", "compile"):
                stack.enter_context(mock.patch.object(builtins, name, new=forbidden))
            pf = _parse(source)
            index = PolyglotIndex(files={pf.path: pf})
            graph = Graph()
            build_polyglot_graph(graph, index)
            analyze_polyglot_security(graph, index)
        self.assertEqual([s.name for s in pf.symbols], ["main"])

    def test_redos_long_lines_and_nested_widgets_finish_in_child_process(self) -> None:
        # A child deadline makes a future regex regression fail without hanging
        # the test runner. Never execute the old vulnerable expression itself.
        script = textwrap.dedent('''
            import json
            import sys
            sys.path.insert(0, sys.argv[1])
            from secdiagram_core.polyglot_index import parse_polyglot_file
            samples = [
                'Future<' + 'List<' * 100 + 'int' + '>' * 101 + ' missing',
                'a ' * 200000,
                ' ' * 200000 + 'noParen',
                'void main() { return Widget(' + 'Widget(' * 20000 + ')' * 20001 + '; }',
                '/*' * 20000 + '*/' * 20000 + '\\nvoid fine() {}',
                'void broken(' + '(' * 20000,
                'const s = "' + '${"' * 10000 + 'void fake() {}' + '"}' * 10000 + '";',
                '\\n' * 50000 + 'void fine() {}' * 10000,
            ]
            for text in samples:
                pf = parse_polyglot_file('hostile.dart', text)
                assert pf is not None
                assert all(s.name in ('main', 'fine') for s in pf.symbols)
            print(json.dumps({'cases': len(samples)}))
        ''')
        env = {"PYTHONIOENCODING": "utf-8"}
        if "SYSTEMROOT" in os.environ:
            env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [sys.executable, "-I", "-c", script, str(Path(__file__).resolve().parents[1])],
                cwd=tmp, env=env, capture_output=True, text=True, timeout=20, check=True,
            )
        self.assertEqual(json.loads(result.stdout), {"cases": 8})


if __name__ == "__main__":
    unittest.main()
