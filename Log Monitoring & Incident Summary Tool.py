#!/usr/bin/env python3
"""
Log Monitoring & Incident Summary Tool
Parses application logs, groups errors into incidents, detects spikes,
and exports TXT, CSV, and JSON reports.
"""

import argparse
import csv
import json
import logging
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional


# Supported text format:
# 2026-10-15 09:30:00 ERROR payment-service - Payment gateway timeout
TEXT_LOG_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\s+"
    r"(?P<level>[A-Za-z]+)\s+"
    r"(?P<service>[\w.-]+)\s*[-:]?\s*"
    r"(?P<message>.*)$"
)

ERROR_LEVELS = {"ERROR", "CRITICAL", "FATAL", "SEVERE"}
EXCEPTION_MARKERS = ("exception", "traceback", "failed", "failure")


@dataclass
class LogRecord:
    timestamp: datetime
    level: str
    service: str
    message: str
    source_line: int


@dataclass
class Incident:
    service: str
    error_type: str
    count: int
    first_occurrence: str
    last_occurrence: str
    sample_message: str
    spike_detected: bool = False
    peak_window_count: int = 0


def setup_logging(verbose: bool = False) -> None:
    """Configure application logging."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def parse_timestamp(value: Any) -> datetime:
    """Parse common timestamp representations."""
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value)
    if not isinstance(value, str):
        raise ValueError("Timestamp must be a string or Unix timestamp")

    value = value.strip()
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
                    "%Y/%m/%d %H:%M:%S", "%d-%m-%Y %H:%M:%S"):
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue
    raise ValueError(f"Unsupported timestamp: {value}")


def parse_json_log(line: str, line_number: int) -> Optional[LogRecord]:
    """Parse a JSON log line using common field-name aliases."""
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None

    timestamp = obj.get("timestamp", obj.get("time", obj.get("@timestamp")))
    level = obj.get("level", obj.get("severity", obj.get("log_level", "INFO")))
    service = obj.get("service", obj.get("application", obj.get("logger", "unknown-service")))
    message = obj.get("message", obj.get("msg", obj.get("error", "")))