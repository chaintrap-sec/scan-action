"""Build npm tarballs and registry index from sandbox corpus packages."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CORPUS = ROOT / "corpus" / "packages"
ARTIFACTS = ROOT / "artifacts"


def _make_tgz(pkg_dir: Path, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for path in sorted(pkg_dir.rglob("*")):
            if not path.is_file():
                continue
            arc = f"package/{path.relative_to(pkg_dir).as_posix()}"
            tf.add(path, arcname=arc)
    out_path.write_bytes(buf.getvalue())


def _ensure_miasma_dropper(pkg_dir: Path) -> None:
    """Generate oversized obfuscated dropper if not present."""
    dropper = pkg_dir / "index.js"
    if dropper.is_file() and dropper.stat().st_size > 400_000:
        return
    header = (
        "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+"
        "((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};"
        "if(!''.replace(/^/,String)){while(c--)d[e(c)]=k[c]||e(c);k=[function(e){return d[e]}];"
        "e=function(){return'\\\\w+'};c=1;};while(c--)if(k[c])p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c]);"
        "return p;}('Miasma: The Spreading Blight',62,62,''.split('|'),0,{}));\n"
        "var _0x4a2f=['trufflehog','gh auth token'];\n"
    )
    # Pad with high-entropy hex escapes to simulate 4MB obfuscated dropper.
    pad = "\\x" + "41" * 4
    body = (pad * 120_000) + "\n"
    dropper.write_text(header + body, encoding="utf-8")


def build() -> Path:
    index: dict = {"npm": {}, "pypi": {}}
    ARTIFACTS.mkdir(parents=True, exist_ok=True)

    for eco_dir in sorted(CORPUS.iterdir()):
        if not eco_dir.is_dir():
            continue
        eco = eco_dir.name
        for sample_dir in sorted(eco_dir.iterdir()):
            if not sample_dir.is_dir():
                continue
            meta_path = sample_dir / "sample.json"
            if not meta_path.is_file():
                continue
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            name = str(meta["name"])
            version = str(meta["version"])
            sample_id = sample_dir.name

            if eco == "npm" and sample_id == "miasma-obfuscated":
                _ensure_miasma_dropper(sample_dir)

            artifact_name = f"{eco}-{sample_id}-{version}.tgz"
            if eco == "pypi":
                artifact_name = f"{eco}-{sample_id}-{version}.tar.gz"
            out = ARTIFACTS / artifact_name
            _make_tgz(sample_dir, out)

            index.setdefault(eco, {}).setdefault(name, {})[version] = {
                "artifact": artifact_name,
                "sample_id": sample_id,
            }

    (ARTIFACTS / "index.json").write_text(json.dumps(index, indent=2), encoding="utf-8")
    return ARTIFACTS


if __name__ == "__main__":
    out = build()
    print(f"Built artifacts in {out}")
