# LLMShield 🛡️

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Security scanner for ML models and code - detects malicious code, backdoors, and embedded secrets.

## Installation

```bash
git clone https://github.com/jay123-1/llmshield.git
cd llmshield
pip install -r requirements.txt
pip install -e .
```

## Usage

```bash
# Scan a file
llmshield scan model.pkl

# Scan a directory (recursive by default)
llmshield scan /path/to/project/

# Scan with filters
llmshield scan /models/ --size 1GB --extensions .pkl .pth .py
```

## Updating Detection Rules

LLMShield uses YAML-based detection rules that can be easily customized:

### Rule Files Location
```
config/
├── secret_detection_rules.yaml    # API keys, tokens, passwords
├── ml_security_rules.yaml         # ML-specific threats
├── code_execution_rules.yaml      # Dangerous code patterns
└── model_backdoor_rules.yaml      # Known backdoor signatures
```

### Adding New Rules

1. **Edit the appropriate YAML file:**
```yaml
# Example: Add new API key pattern to secret_detection_rules.yaml
rules:
  my_api_key:
    enabled: true
    name: "My Service API Key"
    description: "Detects My Service API keys"
    patterns:
      - 'myservice_[a-zA-Z0-9]{32}'
    severity: HIGH
    tags: ['api_key', 'myservice']
```

2. **Test your rules:**
```bash
# Create test file with pattern
echo "api_key = 'myservice_abc123def456...'" > test.py

# Run scan
llmshield scan test.py
```

### Disabling Rules

Set `enabled: false` for any rule:
```yaml
rules:
  my_rule:
    enabled: false  # This rule won't run
```

## Supported Formats

**ML Models**: .pkl, .pth, .pt, .bin, .onnx, .pb, .h5, .ckpt  
**Code**: .py, .js, .java, .c, .cpp, .go, .rs, .sh  
**Config**: .json, .yaml, .yml, .env, .conf, .ini, .toml  
**Text**: .txt, .log, .md, .xml

## Output Formats

```bash
# JSON report
llmshield scan model.pkl -f json -o report.json

# HTML report with interactive filtering
llmshield scan /project/ -f html -o report.html

# Text output (default)
llmshield scan file.py
```

## Examples

```bash
# Scan Python project for secrets
llmshield scan /my_project/ --extensions .py .env .json

# Scan ML models only
llmshield scan /models/ --ml-only

# Generate security report
llmshield scan /production/models/ -f html -o security_report.html
```

## HuggingFace Integration

Pull and scan models from HuggingFace:

```bash
# Public models (no auth required)
llmshield pull huggingface://microsoft/DialoGPT-medium --scan

# Private models (auth required)
export HF_TOKEN="hf_xxxxxxxxxxxxxxxxxxxx"
llmshield pull huggingface://your-org/private-model --scan
```

### Setting up HuggingFace Token

1. Get token from [huggingface.co/settings/tokens](https://huggingface.co/settings/tokens)
2. Set via environment variable:
   ```bash
   export HF_TOKEN="your_token_here"
   ```
   Or add to `~/.llmshield/config.yaml`:
   ```yaml
   huggingface:
     api_token: "your_token_here"
   ```

## License

MIT License - see [LICENSE](LICENSE) file