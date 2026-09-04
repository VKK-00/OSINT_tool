from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path("corpus")
OUT = Path("research/uvb76_outputs")
OUT.mkdir(parents=True, exist_ok=True)

inventory = []
for path in sorted(ROOT.rglob("*")):
    if not path.is_file():
        continue
    item = {
        "path": path.as_posix(),
        "bytes": path.stat().st_size,
        "suffix": path.suffix.lower(),
    }
    if path.suffix.lower() == ".csv":
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            rows = []
            count = 0
            for row in reader:
                count += 1
                if len(rows) < 5:
                    rows.append(row)
            item["columns"] = reader.fieldnames or []
            item["row_count"] = count
            item["sample_rows"] = rows
    elif path.suffix.lower() == ".json" and path.stat().st_size < 2_000_000:
        try:
            item["json"] = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            item["json_error"] = f"{type(exc).__name__}: {exc}"
    inventory.append(item)

summary = {
    "root_exists": ROOT.exists(),
    "file_count": len(inventory),
    "files": inventory,
}
(OUT / "inspection.json").write_text(
    json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
)
print(json.dumps({
    "file_count": len(inventory),
    "csvs": [
        {"path": x["path"], "rows": x.get("row_count"), "columns": x.get("columns")}
        for x in inventory if x["suffix"] == ".csv"
    ],
}, ensure_ascii=False, indent=2))
