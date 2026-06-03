# Java Parser Pipeline

A tree-sitter-based parser for extracting methods, building call graphs, and generating OpenAnt dataset format from Java codebases.

## Architecture

The parser follows the same 4-stage pipeline as the Python / C / Ruby parsers:

```
Stage 1: RepositoryScanner  →  Find .java files
Stage 2: FunctionExtractor  →  Extract methods/constructors via tree-sitter
Stage 3: CallGraphBuilder   →  Build bidirectional call graph
Stage 4: UnitGenerator      →  Generate dataset.json + analyzer_output.json
```

## Dependencies

```bash
pip install tree-sitter tree-sitter-java
```

## Quick Start

```bash
# Basic run (all units)
python parsers/java/test_pipeline.py /path/to/repo --output datasets/myrepo

# With reachability filtering (recommended)
python parsers/java/test_pipeline.py /path/to/repo --output datasets/myrepo --processing-level reachable --skip-tests

# With CodeQL pre-filter
python parsers/java/test_pipeline.py /path/to/repo --output datasets/myrepo --processing-level codeql --skip-tests

# With LLM enhancement
python parsers/java/test_pipeline.py /path/to/repo --output datasets/myrepo --processing-level reachable --llm --agentic
```

You can also run via the unified CLI which auto-detects Java:

```bash
openant parse /path/to/java/repo -o /tmp/out
openant parse /path/to/java/repo -o /tmp/out --language java
```

## Processing Levels

| Level | Filter | Description |
|-------|--------|-------------|
| `all` | None | Process all units (no filtering) |
| `reachable` | Entry point reachability | Filter to units reachable from entry points |
| `codeql` | Reachable + CodeQL | Add CodeQL static analysis pre-filter (`codeql/java-queries`) |
| `exploitable` | Reachable + CodeQL + LLM | Maximum cost savings with LLM classification |

## Stage Details

### Stage 1: Repository Scanner (`repository_scanner.py`)

Scans for source files with extension `.java`.

**Excluded directories (defaults):** `.git`, `.svn`, `.hg`, `.idea`, `.gradle`, `.mvn`, `target`, `build`, `out`, `bin`, `classes`, `generated`, `generated-sources`, `node_modules`, `dist`, `.cache`, `doc`, `docs`, hidden directories (`.`).

**`--skip-tests` flag:** Filters files in `src/test/`, `src/it/`, `test/`, `tests/`, or matching `*Test.java`, `*Tests.java`, `*IT.java`, `*TestCase.java`.

### Stage 2: Function Extractor (`function_extractor.py`)

Uses tree-sitter to parse Java source and extract:
- Method declarations (`method_declaration`)
- Constructors (`constructor_declaration`, `compact_constructor_declaration`)
- Static initializers (`static_initializer`) -- exposed as `<clinit>` units
- Per-file `package` declaration and `import` list (used for call resolution)
- Class metadata: name, kind (`class` / `interface` / `enum` / `record` / `annotation_type`), superclass, interfaces, modifiers, annotations, nested types
- Method modifiers (`public`/`private`/`static`/`abstract`/`native`/`synchronized`/...) and annotations (`@Override`, `@GetMapping`, `@Test`, ...)

**Function ID format:** `relative/path.java:Outer.Inner.method#<arity>`

The `#<arity>` suffix disambiguates Java overloads (e.g. `Foo.bar#1` vs `Foo.bar#2`).

**Unit type classification:**

| Type | Detection |
|------|-----------|
| `main` | name == `main` and `static` modifier |
| `constructor` | constructor or compact constructor |
| `static_initializer` | `static { ... }` block |
| `route_handler` | `@GetMapping` / `@PostMapping` / `@RequestMapping` / `@Path` / JAX-RS verbs / Servlet `doGet`/`doPost`/etc. / `*Controller` class with mapping annotation |
| `test` | `@Test` / `@ParameterizedTest` / JUnit `@Before*` / `@After*` / TestNG equivalents |
| `abstract_method` | has `abstract` modifier |
| `native_method` | has `native` modifier |
| `static_method` | has `static` modifier |
| `private_method` | has `private` modifier |
| `method` | default |

### Stage 3: Call Graph Builder (`call_graph_builder.py`)

Walks function bodies for `method_invocation`, `object_creation_expression`, and `explicit_constructor_invocation` nodes. Resolution heuristics:

1. **Bare `foo(...)` / `this.foo(...)`** — search the enclosing class, walk one level up the superclass chain by simple name, then fall back to a unique-name match.
2. **`super.foo(...)`** — resolve against the declared superclass (best-effort, by simple name).
3. **`Class.foo(...)`** (receiver starts with an uppercase letter) — resolve via same package, then `import` list, then unique simple-class name.
4. **`new Foo(...)`** — locate a constructor with matching arity in the same package or imports.
5. **`this(...)` / `super(...)`** — explicit constructor delegation.
6. **Unresolved** — left out (likely external library, no IDs leaked into the call graph).

Common JDK and standard-library methods (`equals`, `toString`, `size`, `add`, `println`, SLF4J / `java.util.Logging`, JDBC `executeQuery`, Servlet API, etc.) are filtered out via `JAVA_BUILTINS`. This avoids the unique-name fallback gluing every `size()` to one repo method.

Arity-aware matching disambiguates Java overloads where possible.

### Stage 4: Unit Generator (`unit_generator.py`)

Generates `dataset.json` and `analyzer_output.json` with the same schema as the Python / C / Ruby parsers.

**File boundary marker:** `// ========== File Boundary ==========` (Java-style comment)

## Output Files

| File | Description |
|------|-------------|
| `scan_results.json` | File listing from scanner |
| `call_graph.json` | Intermediate call-graph data (consumed by the unified reachability filter in `core/parser_adapter.py`) |
| `dataset.json` | OpenAnt dataset format (input to `experiment.py` / `openant analyze`) |
| `analyzer_output.json` | Function metadata with camelCase fields (used by Stage 2 verification tools) |
| `pipeline_results.json` | Pipeline execution summary |
| `codeql-db/` | CodeQL database (only at `--processing-level codeql` or `exploitable`) |
| `codeql-results.sarif` | CodeQL findings (only at `--processing-level codeql` or `exploitable`) |

## Design Decisions

### Why tree-sitter over `javac` / Eclipse JDT?

- **No build environment needed** — `javac` would require resolved classpaths, dependency JARs, generated sources (annotation processors, Lombok, ...). Tree-sitter happily parses `.java` files in isolation.
- **Error-tolerant** — produces a tree even for files with unresolvable imports.
- **Fast** — tree-sitter is written in C internally.
- **No JVM dependency** — pure `pip install` works.

### Limitations

- Cannot resolve dynamic dispatch / virtual calls precisely. The builder picks the same-class match if available, then walks one level of the superclass chain by simple name; deeper inheritance is not tracked.
- Cannot resolve calls through interfaces to implementing classes (e.g. `userService.find(...)` where `UserService` is an interface and the implementation lives elsewhere). Falls back to unique-name match if exactly one candidate exists.
- Cannot statically resolve reflective calls (`Method.invoke`, `Class.forName(...).getMethod(...).invoke(...)`).
- Generic type arguments are stripped; raw types are used for class lookup.
- Lambda bodies and method references inside lambdas are walked, but the lambda itself is not exposed as its own unit (calls inside the lambda are attributed to the enclosing method).
- Annotation processors / generated sources are not resolved unless the generated `.java` files are present in the source root.
- Inner / anonymous classes declared inside method bodies are not extracted as separate units (their methods stay inside the enclosing method's `code` field).

## Notes for Large Repos

For very large Java codebases (e.g. Snowflake's `GlobalServices`):

- Always pass `--skip-tests` to drop `src/test/`, JUnit, and `*IT.java` files.
- Start with `--processing-level reachable`; the unfiltered call graph for hundreds of thousands of methods is large.
- The pipeline subprocess timeout is 30 minutes (matches the C parser). Increase via the `core/parser_adapter._parse_java` `timeout=` argument if you need more.
- Reachability detection works best when the codebase has clear entry points (`main` methods, `@RestController` classes, servlet `doGet`/`doPost`). For pure-library codebases consider `--processing-level all` with a downstream LLM filter.
