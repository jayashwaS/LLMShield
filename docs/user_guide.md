# LLMShield User Guide

## Table of Contents
- [Overview](#overview)
- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Advanced Features](#advanced-features)
- [Supported Formats](#supported-formats)
- [Output Reports](#output-reports)
- [Best Practices](#best-practices)

## Overview

LLMShield is a comprehensive security scanner designed to detect vulnerabilities, backdoors, and embedded secrets in machine learning models and code files. It supports over 40 file formats and includes 9 specialized security scanners.

## Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Virtual environment (recommended)
- 4GB RAM minimum (8GB recommended for large models)
- 2GB disk space for installation

### Step-by-Step Installation

1. **Clone the repository**
```bash
git clone https://github.com/jay123-1/llmshield.git
cd llmshield
```

2. **Create virtual environment**
```bash
python -m venv venv
```

3. **Activate virtual environment**
```bash
# Linux/macOS
source venv/bin/activate

# Windows
venv\Scripts\activate
```

4. **Install dependencies**
```bash
pip install -r requirements.txt
```

5. **Install LLMShield**
```bash
pip install -e .
```

6. **Verify installation**
```bash
llmshield --version
llmshield --help
```

## Basic Usage

### Scanning Files

#### Single File Scan
```bash
# Scan a model file
llmshield scan model.pkl
llmshield scan model.pth
llmshield scan model.onnx

# Scan source code
llmshield scan config.py
llmshield scan app.js

# Scan configuration files
llmshield scan config.yaml
llmshield scan .env
```

#### Directory Scan
```bash
# Scan a directory (non-recursive)
llmshield scan /path/to/models/

# Scan recursively
llmshield scan /path/to/models/ --recursive

# Scan specific file types
llmshield scan /path/to/models/ --extensions .pkl .pth .py
```

### Common Options

| Option | Description | Example |
|--------|-------------|---------|
| `-o, --output` | Output directory | `--output reports/` |
| `-f, --format` | Report format | `-f json -f html` |
| `-r, --recursive` | Scan subdirectories | `--recursive` |
| `-e, --extensions` | File extensions to scan | `--extensions .pkl .py` |
| `--size` | Max file size | `--size 1GB` |
| `-s, --scanners` | Specific scanners | `--scanners SecretScanner` |

### Examples

```bash
# Scan with size limit
llmshield scan /models/ --size 1GB

# Generate HTML report
llmshield scan model.pkl -f html -o reports/

# Use specific scanners
llmshield scan model.pth --scanners SecretScanner,PickleScanner

# Quick scan without report
llmshield scan model.pkl --no-report
```

## Advanced Features

### Repository Integration

#### HuggingFace
```bash
# Pull model from HuggingFace
llmshield pull --source huggingface bert-base-uncased

# Pull and scan immediately
llmshield pull --source huggingface bert-base-uncased --scan

# Pull specific files
llmshield pull --source huggingface gpt2 --files "*.bin"
```

#### Ollama
```bash
# Pull from Ollama
llmshield pull --source ollama llama2

# Pull and scan
llmshield pull --source ollama llama2 --scan
```

### AI-Enhanced Analysis

Enable AI enrichment for deeper vulnerability insights:

```bash
# Scan with AI enrichment
llmshield scan model.pth --enrich

# Specify AI provider
llmshield scan model.pth --enrich --ai-provider vertex
```

### Batch Processing

```bash
# Process multiple directories
llmshield scan /models/ /configs/ /scripts/ --recursive

# Generate combined report
llmshield scan /project/ --recursive -f json -o security_audit.json
```

## Supported Formats

### Machine Learning Models
- **PyTorch**: `.pt`, `.pth`, `.bin`
- **TensorFlow**: `.pb`, `.h5`, `.hdf5`, `.keras`
- **TensorFlow Lite**: `.tflite`, `.lite`
- **ONNX**: `.onnx`
- **SafeTensors**: `.safetensors`
- **JAX/Flax**: `.msgpack`, `.flax`
- **GGUF/GGML**: `.gguf`, `.ggml`, `.q4_0`, `.q4_1`, `.q5_0`, `.q5_1`, `.q8_0`

### Serialization Formats
- **Pickle**: `.pkl`, `.pickle`
- **Joblib**: `.joblib`, `.jbl`
- **NumPy**: `.npy`, `.npz`
- **Checkpoint**: `.ckpt`

### Configuration & Code
- **Configuration**: `.json`, `.yaml`, `.yml`, `.env`, `.conf`, `.cfg`, `.ini`, `.toml`
- **Python**: `.py`
- **JavaScript**: `.js`
- **Java**: `.java`
- **C/C++**: `.c`, `.cpp`, `.h`, `.hpp`
- **Go**: `.go`
- **Rust**: `.rs`
- **Others**: `.swift`, `.r`, `.m`, `.sql`, `.sh`, `.bash`, `.ps1`, `.bat`, `.cmd`
- **Web**: `.html`, `.htm`, `.css`, `.xml`
- **Text**: `.txt`, `.text`, `.log`, `.md`, `.rst`

## Output Reports

### Report Formats

#### JSON Report
```bash
llmshield scan model.pkl -f json -o report.json
```

Contains:
- Detailed vulnerability information
- Line numbers and code snippets
- Severity scores and risk assessment
- Remediation suggestions

#### HTML Report
```bash
llmshield scan model.pkl -f html -o report.html
```

Features:
- Visual dashboard
- Sortable vulnerability table
- Syntax-highlighted code snippets
- Exportable results

#### Text Report
```bash
llmshield scan model.pkl -f text
```

Simple console output for quick reviews.

### Report Structure

```json
{
  "scan_summary": {
    "total_files": 10,
    "total_vulnerabilities": 25,
    "max_severity": "CRITICAL"
  },
  "vulnerabilities": [
    {
      "severity": "CRITICAL",
      "scanner": "SecretScanner",
      "description": "AWS Access Key Detected",
      "file": "config.py",
      "line": 23,
      "remediation": "Use environment variables"
    }
  ]
}
```

## Best Practices

### Security Recommendations

1. **Always scan models from untrusted sources**
   ```bash
   llmshield scan downloaded_model.pkl --scanners all
   ```

2. **Use size limits for large directories**
   ```bash
   llmshield scan /models/ --size 1GB --recursive
   ```

3. **Enable AI enrichment for unknown vulnerabilities**
   ```bash
   llmshield scan suspicious_model.pth --enrich
   ```

4. **Regular scanning in CI/CD**
   ```bash
   # In your CI pipeline
   llmshield scan ./models/ --recursive --format json --output scan_results.json
   ```

### Performance Tips

1. **Use specific scanners for faster scans**
   ```bash
   llmshield scan model.pkl --scanners SecretScanner,PickleScanner
   ```

2. **Filter by extensions in large directories**
   ```bash
   llmshield scan /project/ --extensions .pkl .pth --recursive
   ```

3. **Set appropriate timeouts**
   ```bash
   llmshield scan large_model.bin --timeout 600
   ```

### Common Use Cases

#### Pre-deployment Security Check
```bash
llmshield scan ./models/ --recursive --format json --output security_report.json
```

#### Code Repository Audit
```bash
llmshield scan ./src/ --extensions .py .js .env --scanners SecretScanner,CodeScanner
```

#### HuggingFace Model Verification
```bash
llmshield pull --source huggingface suspicious/model --scan
```

#### Quick Security Assessment
```bash
llmshield scan model.pkl --no-report --summary-only
```

## Troubleshooting

### Common Issues

1. **No parser available for file**
   - Check supported file extensions
   - Ensure file is not corrupted

2. **Scan timeout**
   - Increase timeout: `--timeout 600`
   - Use size limit: `--size 500MB`

3. **Memory issues with large files**
   - Use `--size` flag to skip large files
   - Scan files individually

4. **AI enrichment not working**
   - Check Vertex AI credentials
   - Verify project ID and location

### Getting Help

- Run `llmshield --help` for command options
- Check [GitHub Issues](https://github.com/jay123-1/llmshield/issues)
- See [Configuration Guide](configuration.md) for advanced setup