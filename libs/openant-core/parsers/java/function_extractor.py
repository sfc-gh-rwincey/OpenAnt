#!/usr/bin/env python3
"""
Function Extractor for Java Codebases

Extracts ALL methods, constructors, and static initializers from Java source
files using tree-sitter.  This is Phase 2 of the Java parser - function
inventory.

Usage:
    python function_extractor.py <repo_path> [--output <file>] [--scan-file <scan.json>]

Output (JSON):
    {
        "repository": "/path/to/repo",
        "extraction_time": "2026-05-04T...",
        "functions": {
            "com/example/Foo.java:Foo.bar": {
                "name": "bar",
                "qualified_name": "Foo.bar",
                "fully_qualified_name": "com.example.Foo.bar",
                "file_path": "com/example/Foo.java",
                "package": "com.example",
                "start_line": 10,
                "end_line": 25,
                "code": "public int bar(...) { ... }",
                "class_name": "Foo",
                "parameters": ["int x", "String y"],
                "parameter_types": ["int", "String"],
                "return_type": "int",
                "modifiers": ["public", "static"],
                "is_static": true,
                "is_abstract": false,
                "is_native": false,
                "is_synchronized": false,
                "annotations": ["@Override"],
                "throws": ["IOException"],
                "unit_type": "method"
            }
        },
        "classes": { ... },
        "imports": { "file.java": ["java.util.List", ...] },
        "packages": { "file.java": "com.example" },
        "statistics": { ... }
    }
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import tree_sitter_java as ts_java
from tree_sitter import Language, Parser


JAVA_LANGUAGE = Language(ts_java.language())


# Servlet/JAX-RS/Spring/JUnit annotation hints used for unit_type classification
ROUTE_ANNOTATIONS = {
    'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS',
    'GetMapping', 'PostMapping', 'PutMapping', 'DeleteMapping',
    'PatchMapping', 'RequestMapping',
    'Path',
}
TEST_ANNOTATIONS = {
    'Test', 'ParameterizedTest', 'RepeatedTest', 'TestFactory',
    'BeforeEach', 'AfterEach', 'BeforeAll', 'AfterAll',
    'Before', 'After', 'BeforeClass', 'AfterClass',
}


class FunctionExtractor:
    """
    Extract all methods and classes from Java source files using tree-sitter.

    This is Stage 2 of the Java parser pipeline.
    """

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path).resolve()
        self.functions: Dict[str, Dict] = {}
        self.classes: Dict[str, Dict] = {}
        self.imports: Dict[str, List[str]] = {}
        self.packages: Dict[str, str] = {}

        self.parser = Parser(JAVA_LANGUAGE)

        self.file_cache: Dict[str, bytes] = {}

        self.stats = {
            'total_functions': 0,
            'total_classes': 0,
            'total_methods': 0,
            'total_constructors': 0,
            'total_static_initializers': 0,
            'static_methods': 0,
            'abstract_methods': 0,
            'native_methods': 0,
            'files_processed': 0,
            'files_with_errors': 0,
            'by_type': {},
        }

    def read_file(self, file_path: Path) -> bytes:
        """Read and cache file contents as bytes (tree-sitter needs bytes)."""
        path_str = str(file_path)
        if path_str not in self.file_cache:
            try:
                self.file_cache[path_str] = file_path.read_bytes()
            except Exception as e:
                print(f"Warning: Cannot read {file_path}: {e}", file=sys.stderr)
                self.file_cache[path_str] = b""
        return self.file_cache[path_str]

    def _node_text(self, node, source: bytes) -> str:
        """Extract text from a tree-sitter node."""
        return source[node.start_byte:node.end_byte].decode('utf-8', errors='replace')

    # ------------------------------------------------------------------
    # Top-level extraction (package, imports, type-tree walk)
    # ------------------------------------------------------------------

    def _extract_package(self, tree, source: bytes) -> Optional[str]:
        """Extract `package x.y.z;` declaration."""
        for child in tree.root_node.children:
            if child.type == 'package_declaration':
                # find the scoped_identifier / identifier child
                for c in child.children:
                    if c.type in ('scoped_identifier', 'identifier'):
                        return self._node_text(c, source)
        return None

    def _extract_imports(self, tree, source: bytes) -> List[str]:
        """Extract `import a.b.C;` declarations (including static imports)."""
        imports: List[str] = []
        for child in tree.root_node.children:
            if child.type == 'import_declaration':
                # gather all scoped_identifier / asterisk children
                parts = []
                for c in child.children:
                    if c.type in ('scoped_identifier', 'identifier'):
                        parts.append(self._node_text(c, source))
                    elif c.type == 'asterisk':
                        parts.append('*')
                if parts:
                    # The full path is whichever subnode held the qualified name
                    imports.append(parts[-1] if len(parts) == 1 else '.'.join(parts))
        return imports

    def _extract_modifiers(self, node, source: bytes) -> Tuple[List[str], List[str]]:
        """Return (modifier_keywords, annotation_names) from a `modifiers` child."""
        keywords: List[str] = []
        annotations: List[str] = []
        for child in node.children:
            if child.type == 'modifiers':
                for m in child.children:
                    if m.type in ('marker_annotation', 'annotation'):
                        # @Foo or @Foo(...)
                        for ac in m.children:
                            if ac.type in ('identifier', 'scoped_identifier'):
                                annotations.append(self._node_text(ac, source))
                                break
                    elif m.type not in ('comment',):
                        text = self._node_text(m, source).strip()
                        if text and text not in ('@',):
                            keywords.append(text)
                break
        return keywords, annotations

    def _extract_throws(self, node, source: bytes) -> List[str]:
        """Extract the list of declared exceptions in `throws X, Y`."""
        for child in node.children:
            if child.type == 'throws':
                throws = []
                for c in child.children:
                    if c.type in ('type_identifier', 'scoped_type_identifier',
                                  'generic_type', 'identifier'):
                        throws.append(self._node_text(c, source))
                return throws
        return []

    def _extract_parameters(self, node, source: bytes) -> Tuple[List[str], List[str]]:
        """Extract parameters from a method/constructor declaration.

        Returns (full_parameter_strings, parameter_types).
        """
        params_node = node.child_by_field_name('parameters')
        if params_node is None:
            for c in node.children:
                if c.type == 'formal_parameters':
                    params_node = c
                    break

        if params_node is None:
            return [], []

        params: List[str] = []
        types: List[str] = []
        for child in params_node.children:
            if child.type == 'formal_parameter':
                params.append(self._node_text(child, source).strip())
                # find the type child
                t = child.child_by_field_name('type')
                if t is None:
                    for c in child.children:
                        if c.type.endswith('_type') or c.type in (
                            'type_identifier', 'integral_type', 'floating_point_type',
                            'boolean_type', 'void_type', 'array_type', 'generic_type',
                            'scoped_type_identifier',
                        ):
                            t = c
                            break
                if t is not None:
                    types.append(self._node_text(t, source).strip())
            elif child.type == 'spread_parameter':
                params.append(self._node_text(child, source).strip())
                # take the first type-ish child
                for c in child.children:
                    if c.type.endswith('_type') or c.type in (
                        'type_identifier', 'integral_type', 'generic_type',
                        'scoped_type_identifier',
                    ):
                        types.append(self._node_text(c, source).strip() + '...')
                        break

        return params, types

    def _extract_return_type(self, node, source: bytes) -> str:
        """Extract a method's declared return type, or '' for constructors."""
        t = node.child_by_field_name('type')
        if t is not None:
            return self._node_text(t, source).strip()
        return ''

    def _classify_method(self, name: str, class_name: Optional[str],
                          modifiers: List[str], annotations: List[str],
                          file_path: str, is_constructor: bool) -> str:
        """Classify a method/constructor by its type/purpose."""
        if is_constructor:
            return 'constructor'

        if name == '<clinit>' or name == '__static_init__':
            return 'static_initializer'

        if name == 'main' and 'static' in modifiers:
            return 'main'

        # JUnit / TestNG
        for ann in annotations:
            short = ann.split('.')[-1]
            if short in TEST_ANNOTATIONS:
                return 'test'
            if short in ROUTE_ANNOTATIONS:
                return 'route_handler'
            if short == 'Override' and class_name and 'Servlet' in class_name:
                # `protected void doGet(...)` etc. on servlets
                if name in ('doGet', 'doPost', 'doPut', 'doDelete',
                            'service', 'doHead', 'doOptions'):
                    return 'route_handler'

        # Spring-style controller heuristic
        if class_name and class_name.endswith('Controller'):
            if any(a.endswith('Mapping') or a.endswith('Path')
                   for a in annotations):
                return 'route_handler'

        # JAX-RS / Servlet container methods on a class without annotations
        if name in ('doGet', 'doPost', 'doPut', 'doDelete', 'service'):
            return 'route_handler'

        if 'abstract' in modifiers:
            return 'abstract_method'
        if 'native' in modifiers:
            return 'native_method'
        if 'static' in modifiers:
            return 'static_method'
        if 'private' in modifiers:
            return 'private_method'

        # In an interface body (default / static) we still call it a method.
        return 'method'

    # ------------------------------------------------------------------
    # Type-tree walk (class, interface, enum, record, annotation_type)
    # ------------------------------------------------------------------

    _TYPE_NODES = (
        'class_declaration', 'interface_declaration', 'enum_declaration',
        'annotation_type_declaration', 'record_declaration',
    )

    def _process_type_node(self, node, source: bytes, relative_path: str,
                            package: Optional[str],
                            outer_class: Optional[str]) -> None:
        """Process a type declaration (class/interface/enum/record/annotation)."""
        name_node = node.child_by_field_name('name')
        if name_node is None:
            return
        type_name = self._node_text(name_node, source)

        # Build a qualified type name (Outer.Inner for nested types)
        if outer_class:
            qualified_type = f"{outer_class}.{type_name}"
        else:
            qualified_type = type_name

        # Extract superclass / superinterfaces (best-effort)
        superclass = None
        interfaces: List[str] = []
        for c in node.children:
            if c.type == 'superclass':
                for sc in c.children:
                    if sc.type in ('type_identifier', 'scoped_type_identifier',
                                   'generic_type'):
                        superclass = self._node_text(sc, source)
                        break
            elif c.type in ('super_interfaces', 'extends_interfaces'):
                for ic in c.children:
                    if ic.type == 'type_list':
                        for tc in ic.children:
                            if tc.type in ('type_identifier', 'scoped_type_identifier',
                                            'generic_type'):
                                interfaces.append(self._node_text(tc, source))

        modifiers, annotations = self._extract_modifiers(node, source)

        kind = {
            'class_declaration': 'class',
            'interface_declaration': 'interface',
            'enum_declaration': 'enum',
            'annotation_type_declaration': 'annotation_type',
            'record_declaration': 'record',
        }.get(node.type, 'class')

        class_id = f"{relative_path}:{qualified_type}"
        self.classes[class_id] = {
            'name': type_name,
            'qualified_name': qualified_type,
            'fully_qualified_name': f"{package}.{qualified_type}" if package else qualified_type,
            'file_path': relative_path,
            'package': package,
            'kind': kind,
            'start_line': node.start_point[0] + 1,
            'end_line': node.end_point[0] + 1,
            'superclass': superclass,
            'interfaces': interfaces,
            'modifiers': modifiers,
            'annotations': annotations,
            'outer_class': outer_class,
            'methods': [],
        }
        self.stats['total_classes'] += 1

        # Walk the body
        body = node.child_by_field_name('body')
        if body is None:
            for c in node.children:
                if c.type in ('class_body', 'interface_body', 'enum_body',
                              'annotation_type_body', 'record_body'):
                    body = c
                    break

        if body is None:
            return

        method_names: List[str] = []
        for c in body.children:
            if c.type == 'method_declaration':
                m_name = self._process_method_or_ctor_node(
                    c, source, relative_path, package, qualified_type,
                    is_constructor=False,
                )
                if m_name:
                    method_names.append(m_name)
            elif c.type in ('constructor_declaration', 'compact_constructor_declaration'):
                m_name = self._process_method_or_ctor_node(
                    c, source, relative_path, package, qualified_type,
                    is_constructor=True,
                )
                if m_name:
                    method_names.append(m_name)
            elif c.type == 'static_initializer':
                self._process_static_initializer(
                    c, source, relative_path, package, qualified_type,
                )
                method_names.append('<clinit>')
            elif c.type in self._TYPE_NODES:
                # nested type
                self._process_type_node(c, source, relative_path, package,
                                         qualified_type)
            elif c.type == 'enum_body_declarations':
                # enum has its method block in enum_body_declarations
                for ec in c.children:
                    if ec.type == 'method_declaration':
                        m_name = self._process_method_or_ctor_node(
                            ec, source, relative_path, package, qualified_type,
                            is_constructor=False,
                        )
                        if m_name:
                            method_names.append(m_name)
                    elif ec.type in ('constructor_declaration',
                                     'compact_constructor_declaration'):
                        m_name = self._process_method_or_ctor_node(
                            ec, source, relative_path, package, qualified_type,
                            is_constructor=True,
                        )
                        if m_name:
                            method_names.append(m_name)
                    elif ec.type in self._TYPE_NODES:
                        self._process_type_node(ec, source, relative_path,
                                                 package, qualified_type)

        self.classes[class_id]['methods'] = method_names

    def _process_method_or_ctor_node(self, node, source: bytes,
                                       relative_path: str,
                                       package: Optional[str],
                                       class_name: str,
                                       is_constructor: bool) -> Optional[str]:
        """Process a method or constructor declaration node."""
        name_node = node.child_by_field_name('name')
        if name_node is None:
            return None
        name = self._node_text(name_node, source)

        code = self._node_text(node, source)
        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1
        modifiers, annotations = self._extract_modifiers(node, source)
        parameters, parameter_types = self._extract_parameters(node, source)
        throws = self._extract_throws(node, source)
        return_type = '' if is_constructor else self._extract_return_type(node, source)

        unit_type = self._classify_method(
            name, class_name, modifiers, annotations, relative_path, is_constructor,
        )

        qualified_name = f"{class_name}.{name}"
        fully_qualified_name = (
            f"{package}.{qualified_name}" if package else qualified_name
        )
        # Include arity in the function ID to disambiguate Java overloads.
        func_id = f"{relative_path}:{qualified_name}#{len(parameters)}"

        is_static = 'static' in modifiers
        is_abstract = 'abstract' in modifiers
        is_native = 'native' in modifiers
        is_synchronized = 'synchronized' in modifiers

        func_data = {
            'name': name,
            'qualified_name': qualified_name,
            'fully_qualified_name': fully_qualified_name,
            'file_path': relative_path,
            'package': package,
            'start_line': start_line,
            'end_line': end_line,
            'code': code,
            'class_name': class_name,
            'parameters': parameters,
            'parameter_types': parameter_types,
            'return_type': return_type,
            'modifiers': modifiers,
            'annotations': annotations,
            'throws': throws,
            'is_static': is_static,
            'is_abstract': is_abstract,
            'is_native': is_native,
            'is_synchronized': is_synchronized,
            'is_constructor': is_constructor,
            'unit_type': unit_type,
        }

        self.functions[func_id] = func_data
        self.stats['total_functions'] += 1
        if is_constructor:
            self.stats['total_constructors'] += 1
        else:
            self.stats['total_methods'] += 1
        if is_static:
            self.stats['static_methods'] += 1
        if is_abstract:
            self.stats['abstract_methods'] += 1
        if is_native:
            self.stats['native_methods'] += 1
        self.stats['by_type'][unit_type] = self.stats['by_type'].get(unit_type, 0) + 1

        return name

    def _process_static_initializer(self, node, source: bytes,
                                       relative_path: str,
                                       package: Optional[str],
                                       class_name: str) -> None:
        """Static blocks: ``static { ... }`` -- treated as a synthetic method."""
        code = self._node_text(node, source)
        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1

        qualified_name = f"{class_name}.<clinit>"
        fully_qualified_name = (
            f"{package}.{qualified_name}" if package else qualified_name
        )
        func_id = f"{relative_path}:{qualified_name}#0"

        self.functions[func_id] = {
            'name': '<clinit>',
            'qualified_name': qualified_name,
            'fully_qualified_name': fully_qualified_name,
            'file_path': relative_path,
            'package': package,
            'start_line': start_line,
            'end_line': end_line,
            'code': code,
            'class_name': class_name,
            'parameters': [],
            'parameter_types': [],
            'return_type': '',
            'modifiers': ['static'],
            'annotations': [],
            'throws': [],
            'is_static': True,
            'is_abstract': False,
            'is_native': False,
            'is_synchronized': False,
            'is_constructor': False,
            'unit_type': 'static_initializer',
        }
        self.stats['total_functions'] += 1
        self.stats['total_static_initializers'] += 1
        self.stats['static_methods'] += 1
        self.stats['by_type']['static_initializer'] = (
            self.stats['by_type'].get('static_initializer', 0) + 1
        )

    # ------------------------------------------------------------------
    # File processing
    # ------------------------------------------------------------------

    def process_file(self, file_path: Path) -> None:
        """Process a single Java file."""
        source = self.read_file(file_path)
        if not source:
            self.stats['files_with_errors'] += 1
            return

        try:
            relative_path = str(file_path.relative_to(self.repo_path))
        except ValueError:
            relative_path = str(file_path)

        try:
            tree = self.parser.parse(source)
        except Exception as e:
            print(f"Parse error in {file_path}: {e}", file=sys.stderr)
            self.stats['files_with_errors'] += 1
            return

        self.stats['files_processed'] += 1

        package = self._extract_package(tree, source)
        if package:
            self.packages[relative_path] = package
        self.imports[relative_path] = self._extract_imports(tree, source)

        for child in tree.root_node.children:
            if child.type in self._TYPE_NODES:
                self._process_type_node(child, source, relative_path,
                                          package, outer_class=None)

    def extract_from_scan(self, scan_result: Dict) -> Dict:
        """Extract functions from files listed in a scan result."""
        for file_info in scan_result.get('files', []):
            file_path = self.repo_path / file_info['path']
            self.process_file(file_path)
        return self.export()

    def extract_all(self, files: Optional[List[str]] = None) -> Dict:
        """Extract functions from all Java files or a specific list."""
        if files:
            for file_rel_path in files:
                file_path = self.repo_path / file_rel_path
                if file_path.exists():
                    self.process_file(file_path)
        else:
            for file_path in self.repo_path.rglob('*.java'):
                path_str = str(file_path)
                if any(excl in path_str for excl in (
                    '.git', 'target', 'build', 'out', '.gradle',
                    '.mvn', 'node_modules', '.idea',
                )):
                    continue
                self.process_file(file_path)
        return self.export()

    def export(self) -> Dict:
        """Export extraction results."""
        return {
            'repository': str(self.repo_path),
            'extraction_time': datetime.now().isoformat(),
            'functions': self.functions,
            'classes': self.classes,
            'imports': self.imports,
            'packages': self.packages,
            'statistics': self.stats,
        }


def main():
    """Command line interface."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Extract all functions and classes from a Java repository',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python function_extractor.py /path/to/repo
  python function_extractor.py /path/to/repo --output functions.json
  python function_extractor.py /path/to/repo --scan-file scan_results.json
        '''
    )

    parser.add_argument('repo_path', help='Path to the repository')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--scan-file', help='Use file list from repository scanner output')

    args = parser.parse_args()

    try:
        extractor = FunctionExtractor(args.repo_path)

        if args.scan_file:
            with open(args.scan_file) as f:
                scan_result = json.load(f)
            result = extractor.extract_from_scan(scan_result)
        else:
            result = extractor.extract_all()

        output = json.dumps(result, indent=2)

        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"Extraction complete. Results written to: {args.output}", file=sys.stderr)
            print(f"Total functions: {result['statistics']['total_functions']}", file=sys.stderr)
            print(f"  Methods:               {result['statistics']['total_methods']}", file=sys.stderr)
            print(f"  Constructors:          {result['statistics']['total_constructors']}", file=sys.stderr)
            print(f"  Static initializers:   {result['statistics']['total_static_initializers']}", file=sys.stderr)
            print(f"  Static methods:        {result['statistics']['static_methods']}", file=sys.stderr)
            print(f"  Abstract methods:      {result['statistics']['abstract_methods']}", file=sys.stderr)
            print(f"  Native methods:        {result['statistics']['native_methods']}", file=sys.stderr)
            print(f"Total classes: {result['statistics']['total_classes']}", file=sys.stderr)
            print(f"Files processed: {result['statistics']['files_processed']}", file=sys.stderr)
            if result['statistics']['files_with_errors'] > 0:
                print(f"Files with errors: {result['statistics']['files_with_errors']}", file=sys.stderr)
            print(f"By type:", file=sys.stderr)
            for unit_type, count in sorted(result['statistics']['by_type'].items()):
                print(f"  {unit_type}: {count}", file=sys.stderr)
        else:
            print(output)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
