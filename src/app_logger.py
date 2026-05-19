"""Application logging setup for ZPA Status Mini-SIEM.

Configures a single root logger ("zpa_siem") that writes to BOTH:
  - stdout (so systemd / journald keeps capturing live output)
  - a persistent rotated file (default /var/log/zpa-siem/app.log)

The file handler is best-effort: if the directory is missing or not writable
(typical in dev environments without root), file logging is skipped and a
warning is emitted to stdout. Local runs work without requiring the install
layout.

Usage:
    # In main(), once config is loaded:
    from app_logger import setup_logging, get_logger
    setup_logging(config.app_log_dir, config.app_log_file)

    # In any module:
    from app_logger import get_logger
    log = get_logger(__name__)
"""

import logging
import logging.handlers
import os
import sys
from typing import Optional


_DEFAULT_LOG_DIR = "/var/log/zpa-siem"
_DEFAULT_LOG_FILE = "app.log"
_ROOT_NAME = "zpa_siem"
_FORMAT = "%(asctime)s %(levelname)s [%(name)s] %(message)s"
_DATEFMT = "%Y-%m-%dT%H:%M:%S%z"

_configured = False


def setup_logging(
    log_dir: Optional[str] = None,
    log_file: Optional[str] = None,
    level: int = logging.INFO,
) -> logging.Logger:
    """Configure the root logger. Idempotent — safe to call multiple times.

    Returns the root logger.
    """
    global _configured
    root = logging.getLogger(_ROOT_NAME)
    if _configured:
        return root

    root.setLevel(level)
    root.propagate = False
    formatter = logging.Formatter(_FORMAT, datefmt=_DATEFMT)

    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(formatter)
    root.addHandler(stream)

    target_dir = log_dir or _DEFAULT_LOG_DIR
    target_file = log_file or _DEFAULT_LOG_FILE
    path = os.path.join(target_dir, target_file)
    try:
        os.makedirs(target_dir, exist_ok=True)
        # 10 MB per file, keep 5 rotations as a local safety net even
        # when an external logrotate also manages the file.
        file_handler = logging.handlers.RotatingFileHandler(
            path, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)
    except OSError as exc:
        root.warning("File logging disabled (%s): writing to stdout only", exc)

    _configured = True
    return root


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the zpa_siem root.

    Safe to call at module load time before setup_logging() — the returned
    logger will simply have no handlers until setup_logging() runs, at which
    point log records propagate to the configured root handlers.
    """
    short = name.split(".")[-1] if name else _ROOT_NAME
    return logging.getLogger(f"{_ROOT_NAME}.{short}")
