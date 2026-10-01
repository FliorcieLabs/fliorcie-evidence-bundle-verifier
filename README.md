# Fliorcie Evidence Bundle Verifier

Offline verifier for portable local evidence bundles.

This package validates the shape and integrity of a local evidence bundle
without extracting files, following redirects, or making network requests. A
passing result means the recorded local bytes are internally consistent. It does
not prove external truth, compliance, immutability, or WORM storage.

## Boundary

- `FL-EBV`: offline verification of exported local evidence bundles.
- Expected bundle members: `manifest.json` and `journal.json`.
- No archive extraction, network calls, provider calls, or filesystem writes
  except optional user-requested report output.
- Artifact hashes may be referenced; artifact bytes are not required.

## Quick Start

```bash
python -m pip install -e .
python -m pytest
fl-evidence-verify path/to/run.llmwitness-evidence.zip --json
```

