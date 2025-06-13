# Configuration Guide

## Overview

LLMShield can be configured through multiple methods:
1. Command-line flags (highest priority)
2. Configuration file (`~/.llmshield/config.yaml`)
3. Environment variables
4. Default settings

## Configuration File

### Location

The main configuration file is located at:
- Linux/macOS: `~/.llmshield/config.yaml`
- Windows: `%USERPROFILE%\.llmshield\config.yaml`

### Creating Configuration

```bash
# Create default configuration
llmshield configure

# Or manually create the file
mkdir -p ~/.llmshield
touch ~/.llmshield/config.yaml
```

### Complete Configuration Example

```yaml
# Scanner Configuration
scanner:
  # Severity threshold (critical, high, medium, low, info)
  severity_threshold: medium
  
  # Enabled scanners (all, or list specific ones)
  enabled_scanners: all
  # enabled_scanners:
  #   - SecretScanner
  #   - PickleScanner
  #   - CodeScanner
  
  # Default timeout in seconds
  timeout: 300
  
  # Maximum file size to scan
  max_file_size: "1GB"
  
  # Skip files matching these patterns
  exclude_patterns:
    - "*.log"
    - "*.tmp"
    - "__pycache__/*"

# Reporting Configuration
reporting:
  # Default output formats
  default_format: 
    - json
    - html
  
  # Default output directory
  output_directory: "./llmshield_reports"
  
  # Include code snippets in reports
  include_code_snippets: true
  
  # Maximum snippet length
  max_snippet_length: 200
  
  # Anonymize sensitive data in reports
  anonymize_secrets: true

# AI Enrichment Configuration
ai_enrichment:
  # Enable AI enrichment by default
  enabled: false
  
  # Default AI provider
  default_provider: vertex

# Vertex AI Configuration (Google Cloud)
vertex_ai:
  enabled: true
  project_id: "your-gcp-project-id"
  location: "us-central1"
  model_name: "gemini-2.0-flash-exp"
  
  # Model parameters
  temperature: 0.2
  max_tokens: 8192
  top_p: 0.95
  
  # Request settings
  timeout: 30
  max_retries: 3

# OpenAI Configuration (Alternative)
openai:
  enabled: false
  api_key: "sk-..."  # Or use OPENAI_API_KEY env var
  model: "gpt-4"
  temperature: 0.2
  max_tokens: 4096

# HuggingFace Integration
huggingface:
  # Cache directory for downloaded models
  cache_dir: "~/.cache/huggingface"
  
  # Access token (optional, for private models)
  token: null  # Or use HF_TOKEN env var
  
  # Default download settings
  force_download: false
  resume_download: true

# Ollama Integration
ollama:
  # Ollama API endpoint
  base_url: "http://localhost:11434"
  
  # Default model
  default_model: "llama2"

# Logging Configuration
logging:
  # Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
  level: INFO
  
  # Log file location
  file: "~/.llmshield/llmshield.log"
  
  # Console output
  console: true
  
  # Log format
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# Performance Settings
performance:
  # Number of worker threads
  max_workers: 4
  
  # Memory limit per scan
  memory_limit: "2GB"
  
  # Enable caching
  enable_cache: true
  cache_dir: "~/.llmshield/cache"
  cache_ttl: 3600  # seconds

# Security Settings
security:
  # Sandbox untrusted files
  enable_sandbox: false
  
  # Verify file signatures
  verify_signatures: true
  
  # Block known malicious hashes
  block_malicious: true
  
  # Quarantine suspicious files
  quarantine_dir: "~/.llmshield/quarantine"

# Detection Rules
rules:
  # Path to custom rules file
  custom_rules_path: "~/.llmshield/custom_rules.yaml"
  
  # Auto-update rules
  auto_update: true
  update_interval: 86400  # seconds (24 hours)
  
  # Rule sources
  rule_sources:
    - "https://github.com/jay123-1/llmshield-rules/main/rules.yaml"
```

## Environment Variables

Environment variables override configuration file settings:

### Core Settings
```bash
# Scanner settings
export LLMSHIELD_SEVERITY_THRESHOLD=high
export LLMSHIELD_TIMEOUT=600
export LLMSHIELD_MAX_FILE_SIZE=2GB

# Output settings
export LLMSHIELD_OUTPUT_DIR=/path/to/reports
export LLMSHIELD_OUTPUT_FORMAT=json

# Logging
export LLMSHIELD_LOG_LEVEL=DEBUG
export LLMSHIELD_LOG_FILE=/var/log/llmshield.log
```

### AI Enrichment
```bash
# Vertex AI (Google Cloud)
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/credentials.json
export VERTEX_PROJECT_ID=your-project-id
export VERTEX_LOCATION=us-central1
export VERTEX_MODEL=gemini-2.0-flash-exp

# OpenAI
export OPENAI_API_KEY=sk-...
export OPENAI_MODEL=gpt-4
```

### Repository Integration
```bash
# HuggingFace
export HF_TOKEN=hf_...
export HF_HOME=~/.cache/huggingface

# Ollama
export OLLAMA_HOST=http://localhost:11434
```

## Detection Rules Configuration

### Main Rules File

Located at `config/detection_rules.yaml`:

```yaml
# Global settings
settings:
  # Enable/disable all rules
  all_rules_enabled: true
  
  # Rule update settings
  auto_update: true
  update_url: "https://github.com/jay123-1/llmshield-rules"

# Secret detection rules
secrets:
  aws_access_key:
    name: "AWS Access Key"
    enabled: true
    patterns:
      - "AKIA[A-Z0-9]{16}"
    severity: "CRITICAL"
    description: "AWS Access Key ID detected"
    remediation: "Remove hardcoded AWS credentials"
    tags: ["aws", "cloud", "credentials"]
    
  github_token:
    name: "GitHub Personal Access Token"
    enabled: true
    patterns:
      - "ghp_[A-Za-z0-9_]{36,255}"
      - "github_pat_[A-Za-z0-9_]{36,255}"
    severity: "CRITICAL"
    description: "GitHub token detected"
    remediation: "Revoke token and use environment variables"
    tags: ["github", "vcs", "token"]

# Malicious code patterns
malicious_code:
  eval_usage:
    name: "Eval Function Usage"
    enabled: true
    patterns:
      - "\\beval\\s*\\("
    severity: "HIGH"
    description: "Dynamic code evaluation detected"
    remediation: "Replace eval with safe alternatives"
    tags: ["code-execution", "dangerous-function"]

# LLM-specific security
llm_security:
  prompt_injection:
    name: "Prompt Injection Pattern"
    enabled: true
    patterns:
      - "ignore previous instructions"
      - "disregard all prior"
    severity: "HIGH"
    description: "Potential prompt injection detected"
    remediation: "Sanitize user inputs"
    tags: ["llm", "injection"]

# Entropy-based detection
entropy_rules:
  high_entropy_threshold: 4.5
  min_length: 32
  suspicious_characteristics:
    - has_uppercase: true
    - has_lowercase: true
    - has_digits: true
    - has_special: true
    - looks_random: true
```

### Custom Rules

Create `~/.llmshield/custom_rules.yaml`:

```yaml
# Custom organization rules
custom_secrets:
  internal_api_key:
    name: "Internal API Key"
    patterns:
      - "INT_API_[A-Z0-9]{32}"
    severity: "HIGH"
    description: "Internal API key exposed"
    remediation: "Use secure key management"
    
  database_password:
    name: "Database Password"
    patterns:
      - "DB_PASS=['\"]?[^'\"\\s]+"
    severity: "CRITICAL"
    description: "Database password in plain text"
    remediation: "Use environment variables"
```

## Command-Line Overrides

Command-line flags override all other settings:

```bash
# Override severity threshold
llmshield scan model.pkl --severity-threshold critical

# Override timeout
llmshield scan large_model.bin --timeout 600

# Override output format
llmshield scan model.pth --format json --output /tmp/reports/

# Disable specific scanners
llmshield scan model.pkl --disable-scanners EntropyScanner,AnomalyScanner

# Force AI enrichment
llmshield scan model.pkl --enrich --ai-provider vertex
```

## Performance Tuning

### For Large Files

```yaml
performance:
  max_workers: 8
  memory_limit: "4GB"
  enable_streaming: true
  chunk_size: "100MB"
```

### For Many Small Files

```yaml
performance:
  max_workers: 16
  enable_cache: true
  batch_size: 50
  parallel_parsing: true
```

### For CI/CD Integration

```yaml
scanner:
  severity_threshold: high
  fail_on_detection: true
  
reporting:
  default_format: 
    - json
  output_directory: "${CI_ARTIFACTS_DIR}"
  
performance:
  max_workers: "${CI_CPU_COUNT}"
  timeout: 300
```

## Security Profiles

### High Security Profile

```yaml
# ~/.llmshield/profiles/high_security.yaml
scanner:
  severity_threshold: low
  enabled_scanners: all
  
security:
  enable_sandbox: true
  verify_signatures: true
  block_malicious: true
  
ai_enrichment:
  enabled: true
  analyze_all_findings: true
```

### Quick Scan Profile

```yaml
# ~/.llmshield/profiles/quick_scan.yaml
scanner:
  severity_threshold: high
  enabled_scanners:
    - SecretScanner
    - PickleScanner
  timeout: 60
  
reporting:
  default_format: 
    - text
  include_code_snippets: false
```

### Development Profile

```yaml
# ~/.llmshield/profiles/development.yaml
scanner:
  severity_threshold: medium
  enabled_scanners:
    - SecretScanner
    - CodeScanner
    
logging:
  level: DEBUG
  
reporting:
  anonymize_secrets: false
  include_code_snippets: true
```

## Using Profiles

```bash
# Use a specific profile
llmshield scan model.pkl --profile high_security

# Create custom profile
llmshield config create-profile my_profile

# List available profiles
llmshield config list-profiles
```

## Troubleshooting Configuration

### Verify Configuration

```bash
# Show current configuration
llmshield config show

# Validate configuration
llmshield config validate

# Reset to defaults
llmshield config reset
```

### Common Issues

1. **Configuration not loading**
   ```bash
   # Check file location
   llmshield config path
   
   # Verify YAML syntax
   llmshield config validate
   ```

2. **Environment variables not working**
   ```bash
   # Check environment
   llmshield config env
   ```

3. **AI enrichment failing**
   ```bash
   # Test AI configuration
   llmshield config test-ai
   ```

## Configuration Best Practices

1. **Use profiles** for different environments (dev, staging, prod)
2. **Store sensitive data** in environment variables, not config files
3. **Version control** your detection rules
4. **Regularly update** rules from official sources
5. **Monitor performance** and adjust workers/memory as needed
6. **Enable logging** for troubleshooting
7. **Use severity thresholds** appropriate to your risk tolerance
8. **Test configuration** changes in a safe environment first