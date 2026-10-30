"""Application logging. Avoid writing secrets or raw log payloads."""

from __future__ import annotations

import logging
import os
from pathlib import Path

_CONFIGURED = False
_REDACT_KEYS = (
    "TINYFISH_API_KEY",
    "OPENAI_API_KEY",
)


class _RedactFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        message = str(record.getMessage())
        for key in _REDACT_KEYS:
            value = os.getenv(key, "")
            if value and len(value) > 3 and value in message:
                record.msg = message.replace(value, f"[redacted:{key}]")
                record.args = ()
        return True


def configure_logging(level: int = logging.INFO) -> logging.Logger:
    global _CONFIGURED
    logger = logging.getLogger("purplesync")
    if _CONFIGURED:
        return logger

    logger.setLevel(level)
    logger.propagate = False

    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s - %(message)s")
    stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    stream.addFilter(_RedactFilter())
    logger.addHandler(stream)

    log_dir = Path("logs")
    try:
        log_dir.mkdir(exist_ok=True)
        file_handler = logging.FileHandler(log_dir / "purplesync.log", encoding="utf-8")
        file_handler.setFormatter(formatter)
        file_handler.addFilter(_RedactFilter())
        logger.addHandler(file_handler)
    except OSError:
        logger.warning("Could not open logs/purplesync.log; console logging only")

    _CONFIGURED = True
    return logger
