# LLMShield 🛡️

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive security scanner for machine learning models and code files, detecting vulnerabilities, backdoors, and embedded secrets.

## Quick Start

### Installation

```bash
# Clone and install
git clone https://github.com/jay123-1/llmshield.git
cd llmshield
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

### Basic Usage

```bash
# Scan a single file
llmshield scan model.pkl
llmshield scan config.py

# Scan a directory
llmshield scan /path/to/models/

# Scan with specific options
llmshield scan /path/to/models/ --recursive --size 1GB --extensions .pkl .pth .py
```

## Key Features

- **🔍 40+ File Formats**: PyTorch, TensorFlow, ONNX, Pickle, Text, Source Code, Config files
- **🚨 9 Security Scanners**: Code execution, secrets, backdoors, malware signatures
- **📊 Multiple Reports**: JSON, HTML, and text formats
- **🤖 AI Analysis**: Enhanced insights with Vertex AI (optional)

## Common Commands

```bash
# List available scanners
llmshield list-scanners

# Scan with specific scanners
llmshield scan model.pth --scanners SecretScanner,PickleScanner

# Generate HTML report
llmshield scan model.pkl -f html -o reports/

# Pull and scan from HuggingFace
llmshield pull --source huggingface model-name --scan

# Configure tool
llmshield configure
```

## Supported File Types

- **ML Models**: .pkl, .pth, .pt, .bin, .onnx, .pb, .h5, .safetensors
- **Code**: .py, .js, .java, .cpp, .c, .go, .rs
- **Config**: .json, .yaml, .yml, .env, .conf, .ini, .toml
- **Text**: .txt, .log, .md, .xml

## Configuration

Create `~/.llmshield/config.yaml`:

```yaml
scanner:
  severity_threshold: medium
  enabled_scanners: all

# Optional: AI enrichment  
vertex_ai:
  enabled: true
  project_id: your-project-id
  location: us-central1
```

## Documentation

For detailed documentation, see the [docs/](docs/) directory:
- [User Guide](docs/user_guide.md) - Complete usage instructions
- [Scanner Reference](docs/scanners.md) - Detailed scanner documentation
- [Configuration Guide](docs/configuration.md) - Advanced configuration options
- [Development Guide](docs/development.md) - Contributing and extending LLMShield

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/jay123-1/llmshield/issues)
- **Security**: Report vulnerabilities via GitHub Security tab