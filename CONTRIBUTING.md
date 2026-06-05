# Contributing

Project by **nizarski**. Pull requests are fine.

If you want to change the crypto design itself, open an issue first so we can talk it through.

## Run tests

```powershell
$env:PYTHONPATH = "src"
python -m lf256
pytest
```

Optional: `pip install -e ".[dev]"`

## Rules I'd appreciate

- Keep changes small and on-topic.
- Core package stays stdlib-only.
- Don't commit `*.lf256.*` or stuff in `artifacts/`.
- If you change wire format or params, update CHANGELOG.md and docs/TECH.md.
- Don't claim NIST/FIPS stuff unless you actually implemented a standard algorithm.
- Real security bugs: email me, don't post a public issue (see SECURITY.md).

Docs live in docs/TECH.md. Write like a human.
