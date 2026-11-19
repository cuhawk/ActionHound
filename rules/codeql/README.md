# ActionHound CodeQL starter queries

Each language directory is a separate query pack. With the CodeQL CLI and a
database extracted from your application, run the matching pack.

```sh
(cd rules/codeql/javascript && codeql pack install)
codeql database analyze /path/to/js-db rules/codeql/javascript --format=sarif-latest --output=javascript.sarif

(cd rules/codeql/python && codeql pack install)
codeql database analyze /path/to/python-db rules/codeql/python --format=sarif-latest --output=python.sarif
```

The JavaScript/TypeScript pack checks request-controlled redirect URIs, inline
Passport state configuration, Mongoose-style object lookups, and remote input
used as a postMessage target origin or a wildcard origin. The Python pack checks remote dataflow to
supported HTTP clients. Review findings against application authorization,
custom state stores, and destination allowlists.
