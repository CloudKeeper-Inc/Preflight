"""python -m cloudkeeper_preflight.email_gen <assessment.json>

Prints the normalised email-input dict for local iteration on the summariser.
"""

from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path

from cloudkeeper_preflight.email_gen.summariser import summarize_for_email


def _load(path: Path) -> dict:
    if path.suffix == ".gz" or path.name.endswith(".json.gz"):
        with gzip.open(path, "rb") as f:
            return json.loads(f.read())
    with path.open() as f:
        return json.load(f)


def main() -> None:
    if len(sys.argv) != 2:
        print(
            "usage: python -m cloudkeeper_preflight.email_gen <assessment.json[.gz]>",
            file=sys.stderr,
        )
        sys.exit(2)
    assessment = _load(Path(sys.argv[1]))
    summary = summarize_for_email(assessment)
    json.dump(summary, sys.stdout, indent=2, default=str)
    print()


if __name__ == "__main__":
    main()
