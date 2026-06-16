from __future__ import annotations

import os
import time
import uuid
from pathlib import Path


def atomic_write_text(
    path: Path,
    content: str,
    *,
    encoding: str = "utf-8",
    max_attempts: int = 6,
) -> None:
    """Write text atomically; retries Windows file-lock contention."""
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    last_error: OSError | None = None

    for attempt in range(max_attempts):
        temp = path.with_name(f"{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
        try:
            temp.write_text(content, encoding=encoding)
            try:
                os.replace(temp, path)
            except OSError:
                if path.exists():
                    path.unlink(missing_ok=True)
                os.replace(temp, path)
            return
        except OSError as exc:
            last_error = exc
            time.sleep(0.05 * (attempt + 1))
        finally:
            temp.unlink(missing_ok=True)

    try:
        path.write_text(content, encoding=encoding)
        return
    except OSError:
        if last_error is not None:
            raise last_error
        raise
