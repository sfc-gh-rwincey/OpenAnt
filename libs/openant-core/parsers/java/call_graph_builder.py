#!/usr/bin/env python3
"""
Call Graph Builder for Java Codebases

Builds bidirectional call graphs from extracted function data:
- Forward graph: function -> functions it calls
- Reverse graph: function -> functions that call it

This is Phase 3 of the Java parser - dependency resolution.

Java specifics:
- ``method_invocation`` nodes are walked for explicit calls (``foo()`` /
  ``obj.foo()`` / ``Class.foo()``).
- ``object_creation_expression`` nodes are walked for ``new Foo(...)``
  constructor calls.
- ``explicit_constructor_invocation`` (``this(...)`` / ``super(...)``) is
  walked for constructor delegation.
- Resolution uses the file's ``package`` + ``imports`` to qualify names
  before looking them up in the repo-wide indexes.

Function IDs include a ``#<arity>`` suffix to disambiguate Java overloads.

Usage:
    python call_graph_builder.py <extractor_output.json> [--output <file>] [--depth <N>]
"""

import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set

import tree_sitter_java as ts_java
from tree_sitter import Language, Parser


JAVA_LANGUAGE = Language(ts_java.language())


# Java SE / common-library calls we never want to resolve (prevents the
# unique-name fallback from gluing every ``size()`` to one repo method).
JAVA_BUILTINS = {
    # Object
    'equals', 'hashCode', 'toString', 'getClass', 'notify', 'notifyAll',
    'wait', 'finalize', 'clone',
    # System
    'currentTimeMillis', 'nanoTime', 'arraycopy', 'getProperty', 'exit',
    'gc', 'lineSeparator', 'getenv',
    # PrintStream / common I/O
    'println', 'print', 'printf', 'write', 'flush', 'close', 'append',
    'read', 'readLine', 'readAllBytes', 'readAllLines',
    # Collection / Map / Iterable
    'size', 'isEmpty', 'contains', 'containsKey', 'containsValue',
    'add', 'addAll', 'remove', 'removeAll', 'removeIf', 'clear',
    'get', 'put', 'putAll', 'putIfAbsent', 'getOrDefault', 'replace',
    'keySet', 'values', 'entrySet', 'forEach', 'iterator', 'spliterator',
    'stream', 'parallelStream', 'collect', 'toList', 'toSet', 'toArray',
    'map', 'flatMap', 'filter', 'reduce', 'count', 'distinct', 'sorted',
    'limit', 'skip', 'peek', 'findFirst', 'findAny', 'anyMatch', 'allMatch',
    'noneMatch', 'min', 'max', 'sum', 'average', 'orElse', 'orElseGet',
    'orElseThrow', 'ifPresent', 'isPresent',
    # String / CharSequence
    'length', 'charAt', 'substring', 'indexOf', 'lastIndexOf', 'startsWith',
    'endsWith', 'replace', 'replaceAll', 'replaceFirst', 'trim', 'strip',
    'split', 'join', 'toLowerCase', 'toUpperCase', 'concat', 'matches',
    'getBytes', 'codePointAt', 'isBlank', 'chars', 'format', 'valueOf',
    # Number / Math
    'intValue', 'longValue', 'doubleValue', 'floatValue', 'byteValue',
    'shortValue', 'parseInt', 'parseLong', 'parseDouble', 'parseFloat',
    'compareTo', 'compare', 'abs', 'min', 'max', 'pow', 'sqrt', 'log',
    'floor', 'ceil', 'round', 'random',
    # Optional / CompletableFuture / Future
    'of', 'ofNullable', 'empty', 'thenApply', 'thenAccept', 'thenCompose',
    'thenCombine', 'whenComplete', 'exceptionally', 'handle',
    'getNow', 'join', 'cancel', 'isDone', 'isCancelled',
    # Logger (SLF4J / java.util.logging / Log4j common)
    'debug', 'info', 'warn', 'error', 'trace', 'fatal', 'log',
    'isDebugEnabled', 'isInfoEnabled', 'isErrorEnabled', 'isTraceEnabled',
    'isWarnEnabled',
    # Threading
    'run', 'start', 'sleep', 'yield', 'interrupt', 'isInterrupted',
    'currentThread', 'join', 'await', 'signal', 'signalAll', 'lock', 'unlock',
    'tryLock', 'getAndSet', 'compareAndSet', 'incrementAndGet',
    'decrementAndGet', 'getAndIncrement', 'getAndDecrement',
    # Builder pattern method names
    'build',
    # Reflective access (handled separately, tons of calls cluster here)
    'invoke', 'getMethod', 'getDeclaredMethod', 'getField', 'getDeclaredField',
    'newInstance', 'getName', 'getSimpleName', 'isAssignableFrom',
    # Annotations / preconditions
    'requireNonNull', 'checkNotNull', 'checkArgument', 'checkState',
    # Date / Time
    'now', 'plus', 'minus', 'plusDays', 'minusDays', 'plusHours', 'minusHours',
    'toEpochMilli', 'toEpochSecond', 'until', 'isBefore', 'isAfter',
    # Servlet (commonly called on the request/response not user code)
    'getParameter', 'getHeader', 'getAttribute', 'setAttribute',
    'getRequestURI', 'getRequestURL', 'getQueryString', 'getMethod',
    'getRemoteAddr', 'sendRedirect', 'sendError', 'setStatus',
    'getSession', 'getOutputStream', 'getWriter',
    # ResultSet / PreparedStatement (java.sql) — calls to the JDBC API itself
    'executeQuery', 'executeUpdate', 'execute', 'next', 'getString', 'getInt',
    'getLong', 'getBoolean', 'getDouble', 'getDate', 'getTimestamp',
    'setString', 'setInt', 'setLong', 'setBoolean', 'setDouble',
    'setDate', 'setTimestamp', 'setNull', 'setObject',
}


class CallGraphBuilder:
    """
    Build bidirectional call graphs from extracted Java function data.

    This is Stage 3 of the Java parser pipeline.
    """

    def __init__(self, extractor_output: Dict, options: Optional[Dict] = None):
        options = options or {}

        self.functions: Dict[str, Dict] = extractor_output.get('functions', {})
        self.classes: Dict[str, Dict] = extractor_output.get('classes', {})
        self.imports: Dict[str, List[str]] = extractor_output.get('imports', {})
        self.packages: Dict[str, str] = extractor_output.get('packages', {})
        self.repo_path = extractor_output.get('repository', '')

        self.max_depth = options.get('max_depth', 3)

        # Call graphs
        self.call_graph: Dict[str, List[str]] = {}
        self.reverse_call_graph: Dict[str, List[str]] = {}

        # Indexes for faster lookup
        self.functions_by_name: Dict[str, List[str]] = {}
        self.functions_by_file: Dict[str, List[str]] = {}
        self.methods_by_class: Dict[str, List[str]] = {}  # qualified class name -> func_ids
        self.methods_by_simple_class: Dict[str, List[str]] = {}  # simple class -> func_ids
        self.classes_by_simple_name: Dict[str, List[str]] = {}
        self.classes_by_fqn: Dict[str, str] = {}

        self._build_indexes()

        self.parser = Parser(JAVA_LANGUAGE)

    # ------------------------------------------------------------------
    # Indexing
    # ------------------------------------------------------------------

    def _build_indexes(self) -> None:
        """Build lookup indexes for faster resolution."""
        for func_id, func_data in self.functions.items():
            name = func_data.get('name', '')
            if name:
                self.functions_by_name.setdefault(name, []).append(func_id)

            file_path = func_data.get('file_path', '')
            if file_path:
                self.functions_by_file.setdefault(file_path, []).append(func_id)

            class_name = func_data.get('class_name')
            if class_name:
                self.methods_by_simple_class.setdefault(
                    class_name.split('.')[-1], []
                ).append(func_id)

                pkg = func_data.get('package')
                if pkg:
                    self.methods_by_class.setdefault(
                        f"{pkg}.{class_name}", []
                    ).append(func_id)
                self.methods_by_class.setdefault(class_name, []).append(func_id)

        for class_id, class_data in self.classes.items():
            simple = class_data.get('name', '')
            fqn = class_data.get('fully_qualified_name', '')
            if simple:
                self.classes_by_simple_name.setdefault(simple, []).append(class_id)
            if fqn:
                self.classes_by_fqn[fqn] = class_id

    def _is_builtin(self, name: str) -> bool:
        """Check if name is a JDK/common-library method we want to ignore."""
        return name in JAVA_BUILTINS

    # ------------------------------------------------------------------
    # Per-function call extraction
    # ------------------------------------------------------------------

    def _extract_calls_from_code(self, caller_id: str) -> Set[str]:
        """Extract function call references from the caller's code."""
        func_data = self.functions.get(caller_id, {})
        code = func_data.get('code', '')
        caller_file = func_data.get('file_path', caller_id.split(':')[0])
        caller_class = func_data.get('class_name')
        caller_package = func_data.get('package')

        if not code:
            return set()

        code_bytes = code.encode('utf-8', errors='replace')
        try:
            tree = self.parser.parse(code_bytes)
        except Exception:
            return self._extract_calls_regex(code, caller_file, caller_class,
                                              caller_package)

        calls: Set[str] = set()
        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            if node.type == 'method_invocation':
                resolved = self._resolve_method_invocation(
                    node, code_bytes, caller_file, caller_class, caller_package,
                )
                if resolved:
                    calls.add(resolved)
            elif node.type == 'object_creation_expression':
                resolved = self._resolve_object_creation(
                    node, code_bytes, caller_file, caller_package,
                )
                if resolved:
                    calls.add(resolved)
            elif node.type == 'explicit_constructor_invocation':
                resolved = self._resolve_explicit_ctor(
                    node, code_bytes, caller_file, caller_class, caller_package,
                )
                if resolved:
                    calls.add(resolved)
            stack.extend(reversed(node.children))

        return calls

    def _node_text(self, node, source: bytes) -> str:
        return source[node.start_byte:node.end_byte].decode('utf-8', errors='replace')

    def _count_arguments(self, node, source: bytes) -> int:
        """Count arguments in a method_invocation/object_creation arg list."""
        arg_list = node.child_by_field_name('arguments')
        if arg_list is None:
            for c in node.children:
                if c.type == 'argument_list':
                    arg_list = c
                    break
        if arg_list is None:
            return 0
        count = 0
        for c in arg_list.children:
            if c.type in ('(', ')', ','):
                continue
            count += 1
        return count

    # ------------------------------------------------------------------
    # Resolution helpers
    # ------------------------------------------------------------------

    def _resolve_method_invocation(self, node, source: bytes,
                                     caller_file: str,
                                     caller_class: Optional[str],
                                     caller_package: Optional[str]) -> Optional[str]:
        """Resolve a `method_invocation` tree-sitter node to a function ID."""
        name_node = node.child_by_field_name('name')
        if name_node is None:
            return None
        method_name = self._node_text(name_node, source)

        arity = self._count_arguments(node, source)

        object_node = node.child_by_field_name('object')
        receiver_text = (
            self._node_text(object_node, source).strip() if object_node else ''
        )

        is_builtin_name = self._is_builtin(method_name)

        # Case 1: bare `foo(...)` -- no receiver
        # Case 2: `this.foo(...)`
        # In both cases we ALWAYS look in the enclosing class first, even if
        # ``method_name`` collides with a JDK-name like `add` or `size` -- the
        # repo author has shadowed the builtin and the local definition wins.
        if not receiver_text or receiver_text == 'this':
            same_class = self._resolve_self_call(method_name, arity, caller_file,
                                                  caller_class, caller_package,
                                                  builtin_blocks_unique=True)
            if same_class is not None:
                return same_class
            return None if is_builtin_name else None  # already exhausted

        # Case 3: `super.foo(...)`
        if receiver_text == 'super':
            if is_builtin_name:
                return None
            return self._resolve_super_call(method_name, arity, caller_file,
                                              caller_class)

        # For receivers we don't own, the builtin filter is correct -- we have
        # no idea what type the receiver is, so a same-named JDK call is far
        # more likely than a same-named repo method.
        if is_builtin_name:
            return None

        # Case 4: receiver is a type identifier (static call) -- e.g. ``Foo.bar()``
        # Heuristic: receiver starts with an uppercase letter and contains no
        # method-call syntax.
        first_segment = receiver_text.split('.')[0].split('(')[0]
        if first_segment and first_segment[0:1].isupper():
            return self._resolve_class_call(receiver_text, method_name, arity,
                                              caller_file)

        # Case 5: chained / unknown receiver -- fall back to unique-name match
        return self._resolve_unique_name(method_name, arity)

    def _resolve_object_creation(self, node, source: bytes,
                                    caller_file: str,
                                    caller_package: Optional[str]) -> Optional[str]:
        """Resolve a `new Foo(...)` expression to the constructor's func ID."""
        type_node = node.child_by_field_name('type')
        if type_node is None:
            for c in node.children:
                if c.type in ('type_identifier', 'scoped_type_identifier',
                              'generic_type'):
                    type_node = c
                    break
        if type_node is None:
            return None

        type_text = self._node_text(type_node, source).strip()
        # Strip generics: ``Foo<Bar>`` -> ``Foo``
        type_text = re.sub(r'<[^>]*>', '', type_text)
        # Bare class name (last segment)
        simple_name = type_text.split('.')[-1]
        if self._is_builtin(simple_name):
            return None

        arity = self._count_arguments(node, source)
        return self._resolve_constructor(simple_name, arity, caller_file,
                                           caller_package)

    def _resolve_explicit_ctor(self, node, source: bytes,
                                  caller_file: str,
                                  caller_class: Optional[str],
                                  caller_package: Optional[str]) -> Optional[str]:
        """Resolve `this(...)` / `super(...)` constructor invocation."""
        text = self._node_text(node, source)
        arity = self._count_arguments(node, source)

        if text.lstrip().startswith('this'):
            if not caller_class:
                return None
            simple = caller_class.split('.')[-1]
            return self._resolve_constructor(simple, arity, caller_file,
                                               caller_package)

        if text.lstrip().startswith('super'):
            if not caller_class:
                return None
            class_data = self._lookup_class_data(caller_class, caller_file,
                                                   caller_package)
            superclass = (class_data or {}).get('superclass')
            if not superclass:
                return None
            simple = re.sub(r'<[^>]*>', '', superclass).split('.')[-1]
            return self._resolve_constructor(simple, arity, caller_file,
                                               caller_package)

        return None

    def _resolve_self_call(self, method_name: str, arity: int, caller_file: str,
                              caller_class: Optional[str],
                              caller_package: Optional[str],
                              builtin_blocks_unique: bool = False) -> Optional[str]:
        """Resolve a no-receiver / `this.` call.

        Search order:
          1. The enclosing class (and its outer class for nested types).
          2. The enclosing class's declared superclass, by simple name.
          3. ``static import`` / unique-name fallback across the repo.

        ``builtin_blocks_unique`` -- when the method name shadows a
        JDK / common-library name (e.g. ``add``, ``size``), still resolve
        same-class / superclass matches but skip the unique-name fallback.
        """
        if caller_class:
            # 1. Same class (and outer classes -- we drop the inner suffix)
            classes_to_check = [caller_class]
            if '.' in caller_class:
                classes_to_check.append(caller_class.rsplit('.', 1)[0])

            for cls in classes_to_check:
                func_id = self._find_in_class(cls, method_name, arity, caller_file)
                if func_id:
                    return func_id

            # 2. Walk superclass chain (best-effort)
            cls_data = self._lookup_class_data(caller_class, caller_file,
                                                 caller_package)
            if cls_data:
                superclass = cls_data.get('superclass')
                if superclass:
                    super_simple = re.sub(r'<[^>]*>', '', superclass).split('.')[-1]
                    func_id = self._find_in_class_simple(
                        super_simple, method_name, arity,
                    )
                    if func_id:
                        return func_id

        # 3. Static import or unique name -- skipped if the name is a JDK builtin
        # (avoids ``size()``-style false positives where every collection call
        # would otherwise glue to a single repo method).
        if builtin_blocks_unique and self._is_builtin(method_name):
            return None
        return self._resolve_unique_name(method_name, arity)

    def _resolve_super_call(self, method_name: str, arity: int, caller_file: str,
                               caller_class: Optional[str]) -> Optional[str]:
        if not caller_class:
            return None
        cls_data = self._lookup_class_data(caller_class, caller_file, None)
        if not cls_data:
            return None
        superclass = cls_data.get('superclass')
        if not superclass:
            return None
        simple = re.sub(r'<[^>]*>', '', superclass).split('.')[-1]
        return self._find_in_class_simple(simple, method_name, arity)

    def _resolve_class_call(self, receiver: str, method_name: str, arity: int,
                              caller_file: str) -> Optional[str]:
        """Resolve `ClassName.method(...)` / `outer.Inner.method(...)` calls."""
        receiver = re.sub(r'<[^>]*>', '', receiver).strip()
        # Take the last contiguous identifier path (drop any leading expression)
        m = re.search(r'([A-Z][\w]*(?:\.[A-Z][\w]*)*)$', receiver)
        if m:
            cls_path = m.group(1)
        else:
            cls_path = receiver
        simple = cls_path.split('.')[-1]
        # Try with same package qualified name if the file context has one
        caller_package = self.packages.get(caller_file)
        if caller_package:
            qual = f"{caller_package}.{simple}"
            func_id = self._find_in_class(qual, method_name, arity, caller_file)
            if func_id:
                return func_id
        # Try imports
        for imp in self.imports.get(caller_file, []):
            if imp == '*' or imp.endswith('.*'):
                continue
            if imp.endswith(f".{simple}"):
                func_id = self._find_in_class(imp, method_name, arity, caller_file)
                if func_id:
                    return func_id
        # Fallback: any class in the repo with that simple name
        return self._find_in_class_simple(simple, method_name, arity)

    def _resolve_constructor(self, simple_class: str, arity: int,
                                caller_file: str,
                                caller_package: Optional[str]) -> Optional[str]:
        """Locate a constructor `<ClassName>(arity args)`."""
        # Try same package
        if caller_package:
            qual = f"{caller_package}.{simple_class}"
            func_id = self._find_in_class(qual, simple_class, arity, caller_file)
            if func_id:
                return func_id
        # Try imports
        for imp in self.imports.get(caller_file, []):
            if imp.endswith(f".{simple_class}"):
                func_id = self._find_in_class(imp, simple_class, arity, caller_file)
                if func_id:
                    return func_id
        # Fallback
        return self._find_in_class_simple(simple_class, simple_class, arity)

    def _resolve_unique_name(self, method_name: str, arity: int) -> Optional[str]:
        """Pick the only candidate for a method name (with matching arity)."""
        candidates = self.functions_by_name.get(method_name, [])
        if not candidates:
            return None

        same_arity = [
            c for c in candidates
            if len(self.functions[c].get('parameters', [])) == arity
        ]
        if len(same_arity) == 1:
            return same_arity[0]

        if len(candidates) == 1:
            return candidates[0]

        return None

    # ------------------------------------------------------------------
    # Per-class search helpers
    # ------------------------------------------------------------------

    def _find_in_class(self, qualified_class: str, method_name: str,
                          arity: int, caller_file: str) -> Optional[str]:
        candidates = self.methods_by_class.get(qualified_class, [])
        return self._pick_arity_match(candidates, method_name, arity)

    def _find_in_class_simple(self, simple_class: str, method_name: str,
                                 arity: int) -> Optional[str]:
        candidates = self.methods_by_simple_class.get(simple_class, [])
        return self._pick_arity_match(candidates, method_name, arity)

    def _pick_arity_match(self, candidates: List[str], method_name: str,
                            arity: int) -> Optional[str]:
        same_name = [
            c for c in candidates
            if self.functions[c].get('name') == method_name
        ]
        if not same_name:
            return None
        same_arity = [
            c for c in same_name
            if len(self.functions[c].get('parameters', [])) == arity
        ]
        if len(same_arity) == 1:
            return same_arity[0]
        if len(same_arity) > 1:
            # Multiple overloads with the same arity -- pick first deterministically.
            return sorted(same_arity)[0]
        if len(same_name) == 1:
            return same_name[0]
        return sorted(same_name)[0] if same_name else None

    def _lookup_class_data(self, class_name: str, caller_file: str,
                              caller_package: Optional[str]) -> Optional[Dict]:
        """Return the class metadata dict for the best-matching class name."""
        # Try fully-qualified
        if class_name in self.classes_by_fqn:
            return self.classes.get(self.classes_by_fqn[class_name])
        # Try same package
        if caller_package:
            fqn = f"{caller_package}.{class_name}"
            if fqn in self.classes_by_fqn:
                return self.classes.get(self.classes_by_fqn[fqn])
        # Try imports
        for imp in self.imports.get(caller_file, []):
            simple = class_name.split('.')[-1]
            if imp.endswith(f".{simple}") and imp in self.classes_by_fqn:
                return self.classes.get(self.classes_by_fqn[imp])
        # Try simple-name
        simple = class_name.split('.')[-1]
        candidates = self.classes_by_simple_name.get(simple, [])
        if len(candidates) == 1:
            return self.classes.get(candidates[0])
        return None

    # ------------------------------------------------------------------
    # Fallback regex extractor
    # ------------------------------------------------------------------

    def _extract_calls_regex(self, code: str, caller_file: str,
                                caller_class: Optional[str],
                                caller_package: Optional[str]) -> Set[str]:
        """Used when tree-sitter parsing of a single function body fails."""
        calls: Set[str] = set()
        pattern = r'(?:([A-Za-z_$][\w$]*)\.)?([A-Za-z_$][\w$]*)\s*\('
        for match in re.finditer(pattern, code):
            receiver = match.group(1)
            name = match.group(2)
            if name in (
                'if', 'while', 'for', 'switch', 'return', 'catch', 'try',
                'synchronized', 'throw', 'new', 'this', 'super', 'instanceof',
            ):
                continue
            arity = -1  # unknown for regex fallback
            is_builtin_name = self._is_builtin(name)
            if not receiver:
                resolved = self._resolve_self_call(name, arity, caller_file,
                                                      caller_class, caller_package,
                                                      builtin_blocks_unique=True)
            elif is_builtin_name:
                continue
            elif receiver and receiver[0:1].isupper():
                resolved = self._resolve_class_call(receiver, name, arity,
                                                       caller_file)
            else:
                resolved = self._resolve_unique_name(name, arity)
            if resolved:
                calls.add(resolved)
        return calls

    # ------------------------------------------------------------------
    # Build / traverse
    # ------------------------------------------------------------------

    def build_call_graph(self) -> None:
        """Build the complete call graph for all functions."""
        for func_id in self.functions:
            calls = self._extract_calls_from_code(func_id)
            valid_calls = [c for c in calls if c in self.functions and c != func_id]
            self.call_graph[func_id] = valid_calls
            for called_id in valid_calls:
                if called_id not in self.reverse_call_graph:
                    self.reverse_call_graph[called_id] = []
                if func_id not in self.reverse_call_graph[called_id]:
                    self.reverse_call_graph[called_id].append(func_id)

    def get_dependencies(self, func_id: str, depth: Optional[int] = None) -> List[str]:
        max_d = depth if depth is not None else self.max_depth
        dependencies: List[str] = []
        visited = {func_id}
        queue = [(func_id, 0)]
        while queue:
            current_id, current_depth = queue.pop(0)
            if current_depth >= max_d:
                continue
            for called_id in self.call_graph.get(current_id, []):
                if called_id not in visited:
                    visited.add(called_id)
                    dependencies.append(called_id)
                    queue.append((called_id, current_depth + 1))
        return dependencies

    def get_callers(self, func_id: str, depth: Optional[int] = None) -> List[str]:
        max_d = depth if depth is not None else self.max_depth
        callers: List[str] = []
        visited = {func_id}
        queue = [(func_id, 0)]
        while queue:
            current_id, current_depth = queue.pop(0)
            if current_depth >= max_d:
                continue
            for caller_id in self.reverse_call_graph.get(current_id, []):
                if caller_id not in visited:
                    visited.add(caller_id)
                    callers.append(caller_id)
                    queue.append((caller_id, current_depth + 1))
        return callers

    def get_statistics(self) -> Dict:
        total_edges = sum(len(calls) for calls in self.call_graph.values())
        num_funcs = len(self.functions)
        out_degrees = [len(self.call_graph.get(f, [])) for f in self.functions]
        in_degrees = [len(self.reverse_call_graph.get(f, [])) for f in self.functions]
        isolated = sum(
            1 for f in self.functions
            if len(self.call_graph.get(f, [])) == 0
            and len(self.reverse_call_graph.get(f, [])) == 0
        )
        return {
            'total_functions': num_funcs,
            'total_edges': total_edges,
            'avg_out_degree': round(total_edges / num_funcs, 2) if num_funcs > 0 else 0,
            'avg_in_degree': round(total_edges / num_funcs, 2) if num_funcs > 0 else 0,
            'max_out_degree': max(out_degrees) if out_degrees else 0,
            'max_in_degree': max(in_degrees) if in_degrees else 0,
            'isolated_functions': isolated,
        }

    def export(self) -> Dict:
        return {
            'repository': self.repo_path,
            'functions': self.functions,
            'classes': self.classes,
            'imports': self.imports,
            'packages': self.packages,
            'call_graph': self.call_graph,
            'reverse_call_graph': self.reverse_call_graph,
            'statistics': self.get_statistics(),
        }


def main():
    """Command line interface."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Build call graphs from extracted Java function data',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python call_graph_builder.py functions.json
  python call_graph_builder.py functions.json --output call_graph.json
  python call_graph_builder.py functions.json --depth 5
        '''
    )

    parser.add_argument('input_file', help='Function extractor output JSON file')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--depth', '-d', type=int, default=3,
                        help='Max dependency resolution depth (default: 3)')

    args = parser.parse_args()

    try:
        with open(args.input_file) as f:
            extractor_output = json.load(f)

        print(f"Processing {len(extractor_output.get('functions', {}))} functions...",
              file=sys.stderr)

        builder = CallGraphBuilder(extractor_output, {'max_depth': args.depth})
        builder.build_call_graph()

        result = builder.export()
        stats = result['statistics']

        print(f"Call graph built:", file=sys.stderr)
        print(f"  Total functions: {stats['total_functions']}", file=sys.stderr)
        print(f"  Total edges: {stats['total_edges']}", file=sys.stderr)
        print(f"  Avg out-degree: {stats['avg_out_degree']}", file=sys.stderr)
        print(f"  Max out-degree: {stats['max_out_degree']}", file=sys.stderr)
        print(f"  Isolated functions: {stats['isolated_functions']}", file=sys.stderr)

        output = json.dumps(result, indent=2)

        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"Output written to: {args.output}", file=sys.stderr)
        else:
            print(output)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
