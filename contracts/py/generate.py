"""regenerate hacktx_contracts/*.py from ../*.schema.json.

usage: python generate.py [out_dir]
"""

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCHEMAS = HERE.parent
PKG = HERE / "hacktx_contracts"
NAMES = ["event", "raw_event", "session_summary", "stats", "attacker_summary"]

HEADER = "# generated from contracts/{name}.schema.json by contracts/py/generate.py. don't edit."

ARGS = [
    "--input-file-type", "jsonschema",
    "--output-model-type", "pydantic_v2.BaseModel",
    "--target-python-version", "3.11",
    "--use-annotated",
    "--field-constraints",
    "--use-double-quotes",
    "--disable-timestamp",
    "--enum-field-as-literal", "all",
    "--use-union-operator",
    "--use-standard-collections",
    "--use-title-as-name",
    "--collapse-root-models",
    "--extra-fields", "forbid",
    "--formatters", "black", "isort",
]


def generate(out_dir: Path = PKG) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for name in NAMES:
        out = out_dir / f"{name}.py"
        # run from the schema dir so relative $refs resolve and the header path is stable
        subprocess.run(
            [sys.executable, "-m", "datamodel_code_generator",
             "--input", f"{name}.schema.json", "--output", str(out),
             "--custom-file-header", HEADER.format(name=name), *ARGS],
            cwd=SCHEMAS, check=True,
        )
        written.append(out)
    return written


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else PKG
    for p in generate(target):
        print(p)
