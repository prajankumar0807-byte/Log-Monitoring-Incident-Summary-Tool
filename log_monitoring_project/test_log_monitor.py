import json
import tempfile
import unittest
from pathlib import Path

from log_monitor import (
    LogRecord,
    build_incidents,
    is_error,
    normalize_error,
    parse_log_line,
)


class LogMonitorTests(unittest.TestCase):
    def test_parse_text_log(self):
        line = "2026-10-15 09:30:00 ERROR payment-service - Payment gateway timeout"
        record = parse_log_line(line, 1)
        self.assertIsNotNone(record)
        self.assertEqual(record.level, "ERROR")
        self.assertEqual(record.service, "payment-service")
        self.assertEqual(record.message, "Payment gateway timeout")

    def test_parse_json_log(self):
        line = json.dumps({
            "timestamp": "2026-10-15T09:30:00",
            "level": "ERROR",
            "service": "checkout",
            "message": "Database unavailable",
        })
        record = parse_log_line(line, 1)
        self.assertIsNotNone(record)
        self.assertEqual(record.service, "checkout")
        self.assertEqual(record.level, "ERROR")

    def test_normalization_groups_numbers(self):
        self.assertEqual(
            normalize_error("Request 123 failed"),
            normalize_error("Request 456 failed"),
        )

    def test_error_detection(self):
        record = LogRecord(
            timestamp=__import__("datetime").datetime(2026, 10, 15, 9, 30),
            level="INFO", service="api", message="Connection failed", source_line=1
        )
        self.assertTrue(is_error(record))

    def test_incident_aggregation_and_spike(self):
        from datetime import datetime
        records = [
            LogRecord(datetime(2026, 10, 15, 9, 30, i), "ERROR", "api",
                      "Database timeout code 100", i + 1)
            for i in range(6)
        ]
        incidents = build_incidents(records, window_minutes=5, spike_threshold=5)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].count, 6)
        self.assertTrue(incidents[0].spike_detected)


if __name__ == "__main__":
    unittest.main()
