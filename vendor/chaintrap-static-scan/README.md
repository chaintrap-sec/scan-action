# chaintrap-static-scan

OSV-only (`api.osv.dev`) batch queries for **npm** and **PyPI** package versions. Used by Chaintrap / DepShield dashboards for static inventory classification (malicious `MAL-*` vs other advisories).

## Install

```bash
pip install -e .
```

## CLI

```bash
chaintrap-static-scan run --input payload.json --sqlite /path/to/osv_static_scan.sqlite
```

`payload.json` may be a single agent-style object (`hostName`, `packages`, …) or `{"source_files": [{"file_name": "x.json", "payload": { ... }}]}`.

## Library

```python
from chaintrap_static_scan.models import PackageKey
from chaintrap_static_scan.pipeline import scan_packages

out = scan_packages([PackageKey("host1", "npm", "lodash", "4.17.21")])
```
