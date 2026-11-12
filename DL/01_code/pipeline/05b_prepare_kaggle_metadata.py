from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--dataset-root",
        required=True,
    )
    parser.add_argument(
        "--owner",
        required=True,
        help="Kaggle username",
    )
    parser.add_argument(
        "--slug",
        default="optc-network-dl-v1-15m",
    )
    parser.add_argument(
        "--title",
        default="OpTC Network DL v1 - 15min",
    )

    args = parser.parse_args()

    if not re.fullmatch(
        r"[a-z0-9][a-z0-9-]{1,48}[a-z0-9]",
        args.slug,
    ):
        raise ValueError(
            "slug should contain lowercase letters, digits, hyphens."
        )

    root = Path(args.dataset_root)

    if not (
        root / "dataset_manifest.json"
    ).exists():
        raise FileNotFoundError(
            root / "dataset_manifest.json"
        )

    metadata = {
        "title": args.title,
        "id": f"{args.owner}/{args.slug}",
        "licenses": [
            {
                "name": "other"
            }
        ],
    }

    path = root / "dataset-metadata.json"
    path.write_text(
        json.dumps(
            metadata,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print(f"[CREATED] {path}")
    print(f"[ID] {metadata['id']}")
    print()
    print(
        "Review dataset/license/privacy before creating the Kaggle Dataset."
    )


if __name__ == "__main__":
    main()
