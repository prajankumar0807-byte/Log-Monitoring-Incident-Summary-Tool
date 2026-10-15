# Log Monitoring & Incident Summary Tool

## Requirements
- Python 3.9 or newer
- No third-party packages are required.

## Files
- `log_monitor.py`: Main application
- `sample.log`: Example input data
- `test_log_monitor.py`: Unit tests
- `reports/`: Default output folder

## Run the tool
```bash
python log_monitor.py sample.log
```

## Export TXT, JSON, and CSV
```bash
python log_monitor.py sample.log --report reports/summary.txt --json reports/summary.json --csv reports/incidents.csv
```

## Configure spike detection
```bash
python log_monitor.py sample.log --window-minutes 5 --spike-threshold 5 --top 10
```

A spike is flagged when the same normalized error from the same service reaches the configured count in one time bucket.

## Run unit tests
```bash
python -m unittest -v test_log_monitor.py
```

## Supported input formats

Text:
`2026-10-15 09:30:00 ERROR payment-service - Payment gateway timeout`

JSON Lines:
`{"timestamp":"2026-10-15T09:30:00","level":"ERROR","service":"payment-service","message":"Payment gateway timeout"}`

## Notes
- Only error-level records and messages containing markers such as `exception`, `traceback`, `failed`, or `failure` are treated as errors.
- Normalization replaces numbers, IP addresses, UUIDs, and hexadecimal values to group similar messages.
- This is a lightweight educational project. Production monitoring should also handle multiline stack traces, time zones, log rotation, and service-specific parsing rules.
