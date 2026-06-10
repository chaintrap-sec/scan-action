# chaintrap-ci

Discover pinned npm and PyPI packages from lockfiles for Chaintrap CI workflows.

## Usage

```python
from pathlib import Path
from chaintrap_ci.discover import discover_packages

items = discover_packages(Path("."), {"npm", "pypi"})
# [{"ecosystem": "npm", "package_spec": "lodash@4.17.21"}, ...]
```

Supported lockfiles: `package-lock.json`, `pnpm-lock.yaml`, `uv.lock`, `requirements.txt`, `poetry.lock`.
