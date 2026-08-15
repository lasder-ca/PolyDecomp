# PolyDecomp

PolyDecomp is a cross-platform, bilingual (English/Japanese) static decompilation and inspection workbench.

It is intentionally designed as a safe, offline-first analysis tool: input files are read locally, no code from the inspected target is executed, and parsers use bounded reads.

## Current capabilities

- Detect common PE/ELF/Mach-O, Java class, Python bytecode, Lua bytecode, WebAssembly and text/JavaScript inputs.
- Extract printable ASCII/UTF-16LE strings with size and count limits.
- Inspect Python `.pyc` bytecode without executing the target program.
- Parse Java `.class` constant pools and surface UTF-8 constants, class names and descriptors.
- Show PE/ELF/Mach-O/WebAssembly metadata and basic headers.
- Export an analysis report as JSON.
- Desktop GUI with English and Japanese UI.
- CLI for repeatable automation.

PolyDecomp does **not** claim source-perfect reconstruction. Native-code decompilation is represented as structured inspection until a dedicated IR/decompiler backend is added.

## Quick start

```bash
python -m polydecomp.cli sample.bin
python -m polydecomp.gui
```

Python 3.11+ is supported.

## Safety model

PolyDecomp never imports or launches an inspected Python module, Java class, native executable, script or bytecode file. Parsing is performed from bytes with conservative bounds. Malformed inputs should produce a structured error instead of executing target-controlled code.

## Development

```bash
python -m unittest discover -s tests -v
python -m compileall -q polydecomp tests
```

## License

MIT
