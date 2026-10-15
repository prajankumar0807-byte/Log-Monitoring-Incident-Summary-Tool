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

    if timestamp is None:
        logging.warning("Skipping JSON log line %d: timestamp is missing", line_number)
        return None
    try:
        parsed_time = parse_timestamp(timestamp)
    except (ValueError, TypeError, OSError) as exc:
        logging.warning("Skipping JSON log line %d: %s", line_number, exc)
        return None

    return LogRecord(
        timestamp=parsed_time,
        level=str(level).upper(),
        service=str(service),
        message=str(message).strip(),
        source_line=line_number,
    )


def parse_text_log(line: str, line_number: int) -> Optional[LogRecord]:
    """Parse a timestamp/level/service/message text log line."""
    match = TEXT_LOG_RE.match(line.strip())
    if not match:
        return None
    try:
        timestamp = parse_timestamp(match.group("timestamp"))
    except ValueError:
        return None
    return LogRecord(
        timestamp=timestamp,
        level=match.group("level").upper(),
        service=match.group("service"),
        message=match.group("message").strip(),
        source_line=line_number,
    )


def parse_log_line(line: str, line_number: int) -> Optional[LogRecord]:
    """Try JSON parsing first, then the supported plain-text format."""
    if not line.strip():
        return None
    return parse_json_log(line, line_number) or parse_text_log(line, line_number)


def is_error(record: LogRecord) -> bool:
    """Return True for error-level logs or messages indicating an exception/failure."""
    if record.level in ERROR_LEVELS:
        return True
    message = record.message.lower()
    return any(marker in message for marker in EXCEPTION_MARKERS)


def normalize_error(message: str) -> str:
    """Normalize variable values so similar errors group together."""
    normalized = message.lower()
    normalized = re.sub(r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b", "<uuid>", normalized)
    normalized = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<ip>", normalized)
    normalized = re.sub(r"\b0x[0-9a-f]+\b", "<hex>", normalized)
    normalized = re.sub(r"\b\d+\b", "<n>", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized or "unspecified error"


def load_logs(path: Path) -> List[LogRecord]:
    """Read and parse a log file, counting malformed lines."""
    records: List[LogRecord] = []
    malformed = 0
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line_number, line in enumerate(handle, start=1):
                record = parse_log_line(line, line_number)
                if record is None:
                    if line.strip():
                        malformed += 1
                    continue
                records.append(record)
    except OSError as exc:
        raise RuntimeError(f"Could not read log file '{path}': {exc}") from exc

    logging.info("Parsed %d records; skipped %d malformed/unsupported lines", len(records), malformed)
    return records


def detect_spikes(
    records: List[LogRecord],
    window_minutes: int,
    spike_threshold: int,
) -> Dict[tuple, int]:
    """
    Find service/error groups whose count in any time bucket reaches threshold.
    Buckets are aligned to the epoch-like minute interval from each record's time.
    Returns {(service, normalized_error): peak_bucket_count}.
    """
    buckets: Dict[tuple, Counter] = defaultdict(Counter)
    for record in records:
        if not is_error(record):
            continue
        error_type = normalize_error(record.message)
        bucket_start = record.timestamp.replace(second=0, microsecond=0)
        minute = (bucket_start.minute // window_minutes) * window_minutes
        bucket_start = bucket_start.replace(minute=minute)
        buckets[(record.service, error_type)][bucket_start] += 1

    spikes = {}
    for key, bucket_counts in buckets.items():
        peak = max(bucket_counts.values(), default=0)
        if peak >= spike_threshold:
            spikes[key] = peak
    return spikes


def build_incidents(
    records: List[LogRecord],
    window_minutes: int = 5,
    spike_threshold: int = 5,
) -> List[Incident]:
    """Aggregate errors by service and normalized error message."""
    errors = [record for record in records if is_error(record)]
    groups: Dict[tuple, List[LogRecord]] = defaultdict(list)
    for record in errors:
        groups[(record.service, normalize_error(record.message))].append(record)

    spikes = detect_spikes(errors, window_minutes, spike_threshold)
    incidents: List[Incident] = []
    for (service, error_type), items in groups.items():
        items.sort(key=lambda item: item.timestamp)
        peak = spikes.get((service, error_type), 0)
        incidents.append(Incident(
            service=service,
            error_type=error_type,
            count=len(items),
            first_occurrence=items[0].timestamp.isoformat(sep=" "),
            last_occurrence=items[-1].timestamp.isoformat(sep=" "),
            sample_message=items[0].message,
            spike_detected=peak > 0,
            peak_window_count=peak,
        ))
    incidents.sort(key=lambda incident: (incident.count, incident.last_occurrence), reverse=True)
    return incidents


def create_summary(records: List[LogRecord], incidents: List[Incident]) -> Dict[str, Any]:
    """Create top-level summary metrics."""
    level_counts = Counter(record.level for record in records)
    services = sorted({record.service for record in records})
    return {
        "generated_at": datetime.now().isoformat(sep=" ", timespec="seconds"),
        "total_log_records": len(records),
        "error_records": sum(incident.count for incident in incidents),
        "service_count": len(services),
        "services": services,
        "log_levels": dict(sorted(level_counts.items())),
        "incident_count": len(incidents),
        "spike_incident_count": sum(1 for incident in incidents if incident.spike_detected),
    }


def write_text_report(path: Path, summary: Dict[str, Any], incidents: List[Incident], top: int) -> None:
    """Write a human-readable incident report."""
    lines = [
        "LOG MONITORING & INCIDENT SUMMARY",
        "=" * 38,
        f"Generated at       : {summary['generated_at']}",
        f"Total log records  : {summary['total_log_records']}",
        f"Error records      : {summary['error_records']}",
        f"Services observed  : {summary['service_count']}",
        f"Incident groups    : {summary['incident_count']}",
        f"Spike incidents    : {summary['spike_incident_count']}",
        f"Services           : {', '.join(summary['services']) or 'None'}",
        f"Log levels         : {summary['log_levels']}",
        "",
        f"TOP INCIDENTS (showing up to {top})",
        "-" * 38,
    ]
    if not incidents:
        lines.append("No errors or incidents were detected.")
    for index, incident in enumerate(incidents[:top], start=1):
        lines.extend([
            f"{index}. Service: {incident.service}",
            f"   Error type       : {incident.error_type}",
            f"   Occurrences      : {incident.count}",
            f"   First occurrence : {incident.first_occurrence}",
            f"   Last occurrence  : {incident.last_occurrence}",
            f"   Spike detected   : {'YES' if incident.spike_detected else 'NO'}",
            f"   Peak window count: {incident.peak_window_count}",
            f"   Sample message   : {incident.sample_message}",
            "",
        ])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def export_json(path: Path, summary: Dict[str, Any], incidents: List[Incident]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"summary": summary, "incidents": [asdict(item) for item in incidents]}
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def export_csv(path: Path, incidents: List[Incident]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(Incident.__dataclass_fields__.keys())
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for incident in incidents:
            writer.writerow(asdict(incident))


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Parse application logs, identify incidents, and detect error spikes."
    )
    parser.add_argument("logfile", help="Path to the input log file")
    parser.add_argument("--report", default="reports/incident_summary.txt",
                        help="Text report output path (default: reports/incident_summary.txt)")
    parser.add_argument("--json", dest="json_path", help="Optional JSON export path")
    parser.add_argument("--csv", dest="csv_path", help="Optional CSV export path")
    parser.add_argument("--top", type=int, default=10, help="Number of incidents shown in TXT report")
    parser.add_argument("--window-minutes", type=int, default=5,
                        help="Time bucket size used for spike detection (default: 5)")
    parser.add_argument("--spike-threshold", type=int, default=5,
                        help="Errors in one time bucket required to flag a spike (default: 5)")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    setup_logging(args.verbose)

    if args.top < 1:
        parser.error("--top must be at least 1")
    if args.window_minutes < 1 or args.window_minutes > 60:
        parser.error("--window-minutes must be between 1 and 60")
    if args.spike_threshold < 1:
        parser.error("--spike-threshold must be at least 1")

    try:
        records = load_logs(Path(args.logfile))
        incidents = build_incidents(records, args.window_minutes, args.spike_threshold)
        summary = create_summary(records, incidents)
        write_text_report(Path(args.report), summary, incidents, args.top)
        if args.json_path:
            export_json(Path(args.json_path), summary, incidents)
        if args.csv_path:
            export_csv(Path(args.csv_path), incidents)
    except (RuntimeError, OSError, ValueError) as exc:
        logging.error("%s", exc)
        return 1

    print(f"Analysis complete. Parsed {summary['total_log_records']} records.")
    print(f"Found {summary['incident_count']} incident groups; "
          f"{summary['spike_incident_count']} spike incidents.")
    print(f"Text report: {args.report}")
    if args.json_path:
        print(f"JSON report: {args.json_path}")
    if args.csv_path:
        print(f"CSV report: {args.csv_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
