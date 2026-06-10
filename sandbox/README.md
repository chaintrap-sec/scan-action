# Chaintrap detection sandbox

Offline mock-registry harness for end-to-end validation of content scan, workflow audit, and known-bad denylist rules. **All samples are synthetic** — nothing is published to npm or PyPI.

## Run

```bash
cd chaintrap-scan-action
pip install -e vendor/chaintrap-static-scan -e vendor/chaintrap-ci pyyaml
python sandbox/run_sandbox.py
```

Exit code `0` = all expected rules detected, no false positives on benign controls.

## Add a sample

1. Add a package tree under `sandbox/corpus/packages/npm/<id>/` with `sample.json` (`name`, `version`).
2. Or add a workflow under `sandbox/corpus/workflows/<name>.yml`.
3. Register in `sandbox/corpus/manifest.json` with `expected_rules` (prefix match) and `benign: true/false`.
4. Re-run `python sandbox/run_sandbox.py`.

## Update known-bad denylist

Edit `data/known_bad_packages.json` (exact `name@version` pins). The sandbox `known-bad-nx` sample validates denylist matching without network.

## Artifacts

`python sandbox/build_artifacts.py` builds tarballs and `sandbox/artifacts/index.json` for the mock registry. `run_sandbox.py` rebuilds automatically.
