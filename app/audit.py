"""Append-only audit log for the remote connector (JSON lines in DATA_DIR/audit.log).

Records event names, timestamps, tool names and OAuth client ids only. Never tool arguments, tool results, tokens,
codes or secrets: callers pass a fixed set of short fields, and anything else is dropped here.
"""
import json
import threading
from datetime import datetime, timezone
from pathlib import Path

ALLOWED_FIELDS = {"tool", "client", "client_name", "github_user_id", "reason"}
MAX_FIELD = 100


class Audit:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def event(self, name: str, **fields) -> None:
        record = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "event": name}
        for key, value in fields.items():
            if key in ALLOWED_FIELDS and value is not None:
                record[key] = str(value)[:MAX_FIELD]
        line = json.dumps(record, ensure_ascii=True) + "\n"
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line)
