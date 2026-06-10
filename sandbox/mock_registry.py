"""Offline mock npm + PyPI registry for sandbox E2E tests."""

from __future__ import annotations

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


class MockRegistry:
    """Serve package metadata and artifact bytes from a local artifact store."""

    def __init__(self, artifact_dir: Path, host: str = "127.0.0.1", port: int = 0) -> None:
        self.artifact_dir = artifact_dir.resolve()
        self.host = host
        self.port = port
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._index = self._load_index()

    def _load_index(self) -> dict[str, Any]:
        path = self.artifact_dir / "index.json"
        if not path.is_file():
            return {"npm": {}, "pypi": {}}
        return json.loads(path.read_text(encoding="utf-8"))

    @property
    def npm_base(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def pypi_base(self) -> str:
        return f"http://{self.host}:{self.port}/pypi"

    def start(self) -> None:
        registry = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: Any) -> None:
                pass

            def _send_json(self, doc: dict[str, Any]) -> None:
                data = json.dumps(doc).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:  # noqa: N802
                parsed = urllib.parse.urlparse(self.path)
                path = parsed.path

                if path.startswith("/artifacts/"):
                    rel = path[len("/artifacts/") :]
                    file_path = registry.artifact_dir / rel
                    if not file_path.is_file():
                        self.send_error(404)
                        return
                    data = file_path.read_bytes()
                    ctype = "application/octet-stream"
                    if rel.endswith(".json"):
                        ctype = "application/json"
                    self.send_response(200)
                    self.send_header("Content-Type", ctype)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return

                if path.startswith("/pypi/") and path.endswith("/json"):
                    parts = path.strip("/").split("/")
                    if len(parts) >= 4:
                        name = urllib.parse.unquote(parts[1])
                        version = parts[2]
                        meta = registry._pypi_meta(name, version)
                        if meta:
                            self._send_json(meta)
                            return
                    self.send_error(404)
                    return

                parts = path.strip("/").split("/")
                name: str | None = None
                version: str | None = None
                if len(parts) == 2:
                    name = urllib.parse.unquote(parts[0])
                    version = parts[1]
                elif len(parts) == 3 and parts[0].startswith("@"):
                    name = urllib.parse.unquote(f"{parts[0]}/{parts[1]}")
                    version = parts[2]
                if name and version:
                    meta = registry._npm_meta(name, version)
                    if meta:
                        self._send_json(meta)
                        return

                self.send_error(404)
        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        self.port = self._server.server_address[1]

        def _run() -> None:
            assert self._server is not None
            self._server.serve_forever()

        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server = None

    def _artifact_url(self, rel: str) -> str:
        return f"{self.npm_base}/artifacts/{rel}"

    def _npm_meta(self, name: str, version: str) -> dict[str, Any] | None:
        entry = (self._index.get("npm") or {}).get(name, {}).get(version)
        if not entry:
            return None
        artifact = str(entry["artifact"])
        return {
            "name": name,
            "version": version,
            "dist": {
                "tarball": self._artifact_url(artifact),
                "shasum": entry.get("shasum", ""),
            },
        }

    def _pypi_meta(self, name: str, version: str) -> dict[str, Any] | None:
        entry = (self._index.get("pypi") or {}).get(name, {}).get(version)
        if not entry:
            return None
        artifact = str(entry["artifact"])
        url = self._artifact_url(artifact)
        is_wheel = artifact.endswith(".whl")
        return {
            "info": {"name": name, "version": version},
            "urls": [
                {
                    "url": url,
                    "packagetype": "bdist_wheel" if is_wheel else "sdist",
                }
            ],
        }
