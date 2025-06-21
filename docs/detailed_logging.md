# LLMShield Detailed Logging Guide

LLMShield now includes comprehensive logging capabilities to help diagnose issues with parsing, rule loading, scanning, and report generation.

## Logging Features

### 1. Dual Logging System
- **Regular Log**: Human-readable format with timestamps and context
- **Detailed JSON Log**: Machine-readable format with complete stack traces and metadata

### 2. Automatic Log Generation
Logs are automatically created in `~/.llmshield/logs/` with timestamps:
- `llmshield_YYYYMMDD_HHMMSS.log` - Regular log file
- `llmshield_detailed_YYYYMMDD_HHMMSS.json` - Detailed JSON log

### 3. Context Tracking
The logger tracks:
- **Component**: Which part of the system (parser, scanner, reporter)
- **Phase**: Current operation (initialization, parsing, scanning, reporting)
- **Duration**: How long each operation takes
- **Errors**: Full stack traces and error details

## CLI Options

```bash
# Set log level (DEBUG, INFO, WARNING, ERROR)
llmshield scan file.pkl --log-level DEBUG

# Specify custom log file location
llmshield scan file.pkl --log-file /path/to/custom.log

# Specify custom detailed log location
llmshield scan file.pkl --detailed-log /path/to/detailed.json

# Enable verbose mode (same as --log-level DEBUG)
llmshield scan file.pkl -v
```

## Log Entry Structure

### Regular Log Format
```
2025-06-20 12:49:17 - llmshield - DEBUG - [component:phase] - filename:line - message
```

### JSON Log Format
```json
{
  "timestamp": "2025-06-20T07:19:17.783834",
  "level": "DEBUG",
  "logger": "llmshield",
  "message": "Loading rules from config",
  "module": "logger",
  "function": "debug",
  "line": 190,
  "file": "logger.py",
  "path": "/path/to/logger.py",
  "process": 79973,
  "thread": 8342457472,
  "component": "rule_loader",
  "phase": "initialization",
  "details": {
    "config_path": "/path/to/detection_rules.yaml"
  }
}
```

## Error Tracking

Errors include:
- Full stack traces
- Error type (e.g., AttributeError, FileNotFoundError)
- Context information
- File paths and line numbers

Example error entry:
```json
{
  "timestamp": "2025-06-20T07:19:17.988309",
  "level": "ERROR",
  "message": "Failed to parse file",
  "error_type": "AttributeError",
  "traceback": "Full Python traceback...",
  "details": {
    "file_path": "/path/to/file.pkl",
    "error": "Detailed error message"
  }
}
```

## Specific Log Events

### 1. Parsing Events
- `log_parsing_start`: When file parsing begins
- `log_parsing_success`: Successful parse with metadata
- `log_parsing_failure`: Parse errors with details

### 2. Rule Loading Events
- `log_rule_loading_start`: Loading detection rules
- `log_rule_loading_success`: Rules loaded with count and categories
- `log_rule_loading_failure`: Rule loading errors

### 3. Scanning Events
- `log_scan_start`: Beginning scan with scanner name
- `log_scan_complete`: Scan finished with vulnerability count
- `log_scan_failure`: Scanner errors with details

### 4. Report Generation Events
- `log_report_generation_start`: Starting report creation
- `log_report_generation_success`: Report created successfully
- `log_report_generation_failure`: Report generation errors

### 5. Scan Summary
At the end of each scan, a comprehensive summary is logged:
```json
{
  "scan_id": "scan_20250620_124917_79973",
  "timestamp": "2025-06-20T07:19:17.000000",
  "files_scanned": 4,
  "total_vulnerabilities": 2,
  "duration_seconds": 1.5,
  "errors": [
    {
      "file": "bad_file.pkl",
      "error": "Invalid pickle format",
      "type": "PickleError"
    }
  ],
  "status": "completed_with_errors"
}
```

## Analyzing Logs

### View Recent Errors
```bash
# Find all errors in regular log
grep ERROR ~/.llmshield/logs/llmshield_*.log

# Extract error entries from JSON log
jq 'select(.level == "ERROR")' ~/.llmshield/logs/llmshield_detailed_*.json
```

### Track Performance
```bash
# Find slow operations (duration > 1 second)
jq 'select(.duration and .duration > 1)' ~/.llmshield/logs/llmshield_detailed_*.json
```

### Debug Specific Component
```bash
# View all parser-related logs
jq 'select(.component == "parser")' ~/.llmshield/logs/llmshield_detailed_*.json

# View all rule loading logs
jq 'select(.component == "rule_loader")' ~/.llmshield/logs/llmshield_detailed_*.json
```

### Create Summary Report
```bash
# Count errors by type
jq -r 'select(.error_type) | .error_type' ~/.llmshield/logs/llmshield_detailed_*.json | sort | uniq -c

# List all scanned files
jq -r 'select(.phase == "parsing" and .level == "DEBUG") | .details.file_path' ~/.llmshield/logs/llmshield_detailed_*.json
```

## Troubleshooting Common Issues

### 1. Parsing Failures
Look for `log_parsing_failure` entries:
```bash
jq 'select(.message | contains("Failed to parse"))' detailed.json
```

### 2. Rule Loading Issues
Check `log_rule_loading_failure` entries:
```bash
jq 'select(.message | contains("Failed to load rules"))' detailed.json
```

### 3. Scanner Errors
Find `log_scan_failure` entries:
```bash
jq 'select(.message | contains("Scanner") and .message | contains("failed"))' detailed.json
```

### 4. Missing Dependencies
Look for import errors:
```bash
jq 'select(.error_type == "ImportError")' detailed.json
```

## Best Practices

1. **Enable Debug Logging for Development**
   ```bash
   llmshield scan file.pkl -v
   ```

2. **Archive Logs Regularly**
   ```bash
   # Compress old logs
   gzip ~/.llmshield/logs/llmshield_*.log
   ```

3. **Monitor Log Size**
   ```bash
   # Check log directory size
   du -sh ~/.llmshield/logs/
   ```

4. **Use JSON Logs for Automation**
   - Parse with jq or Python
   - Send to log aggregation services
   - Create custom monitoring dashboards

## Example: Debug a Failed Scan

```bash
# 1. Run scan with debug logging
llmshield scan suspicious_model.pkl -v

# 2. Check for errors
grep ERROR ~/.llmshield/logs/llmshield_*.log | tail -20

# 3. Get detailed error info
jq 'select(.level == "ERROR") | {file: .details.file_path, error: .error_type, message: .message}' ~/.llmshield/logs/llmshield_detailed_*.json

# 4. View full traceback
jq -r 'select(.level == "ERROR") | .traceback' ~/.llmshield/logs/llmshield_detailed_*.json
```

## Log Rotation

To prevent logs from growing too large, consider setting up log rotation:

```bash
# Create logrotate config
cat > /etc/logrotate.d/llmshield << EOF
$HOME/.llmshield/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
}
EOF
```

## Integration with Monitoring

The JSON logs can be easily integrated with monitoring systems:

1. **Elasticsearch/Logstash**: Stream JSON logs directly
2. **Splunk**: Use the JSON source type
3. **CloudWatch**: Upload logs to AWS
4. **Custom Scripts**: Parse JSON for metrics

Example Python script to extract metrics:
```python
import json
from pathlib import Path

log_file = Path.home() / ".llmshield/logs/llmshield_detailed_latest.json"
errors = []
durations = []

with open(log_file) as f:
    for line in f:
        entry = json.loads(line)
        if entry.get("level") == "ERROR":
            errors.append(entry)
        if "duration" in entry:
            durations.append(entry["duration"])

print(f"Total errors: {len(errors)}")
print(f"Average operation time: {sum(durations)/len(durations):.3f}s")
```