# Security

PolyDecomp is intended to inspect untrusted files without executing them.

## Security boundary

- Target files are read as bytes; they are not imported, launched, evaluated, sourced or loaded as native libraries.
- Parsers must use explicit bounds checks and finite item/size limits.
- New format backends must not invoke target-controlled build scripts, package hooks or runtime initializers.
- External decompiler integrations, when added, must be opt-in and run with an explicit argument vector rather than a shell command string.
- Analysis output should treat extracted strings and symbol names as untrusted display data.

The default in-process analysis limit is 512 MiB per file, with deep inspection bounded to the first 16 MiB. SHA-256 is calculated by streaming the selected file.

## Reporting

Please report security issues privately through GitHub's security reporting channel when available. Do not include sensitive samples in a public issue.
