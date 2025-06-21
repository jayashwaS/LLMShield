# AI Enrichment Guide

## Overview

LLMShield supports AI-powered enrichment to provide deeper insights into detected vulnerabilities using Google Vertex AI with Gemini models.

## Current Implementation

### Supported Provider
- **Google Vertex AI** - Using Gemini models for security analysis

### Enrichment Features
- Vulnerability context and explanations
- Risk assessment and scoring
- Remediation recommendations
- Code intent analysis
- Attack chain visualization
- Compliance impact analysis

## Setup

### 1. Install Google Cloud SDK
```bash
# Install gcloud CLI
curl https://sdk.cloud.google.com | bash

# Authenticate
gcloud auth application-default login
```

### 2. Install Vertex AI Dependencies
```bash
pip install google-cloud-aiplatform
```

### 3. Configure Environment
```bash
# Set your GCP project
export VERTEX_PROJECT_ID="your-project-id"
export VERTEX_LOCATION="us-central1"
export VERTEX_MODEL="gemini-2.0-flash-exp"

# Or use application default credentials
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/credentials.json"
```

### 4. Update Configuration
```yaml
# ~/.llmshield/config.yaml
vertex_ai:
  enabled: true
  project_id: your-project-id
  location: us-central1
  model_name: gemini-2.0-flash-exp
  temperature: 0.2
  max_tokens: 2048
```

## Usage

### Basic Enrichment
```bash
# Scan with AI enrichment
llmshield scan model.pth --enrich

# Disable AI enrichment
llmshield scan model.pth --no-ai
```

### Enrichment Output

AI enrichment adds contextual information to vulnerability reports:

```json
{
  "vulnerability": {
    "severity": "CRITICAL",
    "description": "Dangerous pickle opcode: GLOBAL",
    "ai_insights": {
      "explanation": "This vulnerability allows arbitrary code execution...",
      "risk_assessment": {
        "score": 95,
        "factors": ["Remote code execution", "No authentication required"]
      },
      "remediation": {
        "immediate": "Isolate the model from production",
        "long_term": "Convert to safer serialization formats"
      },
      "attack_scenarios": [
        "Supply chain attack through model repository",
        "Backdoor activation on specific inputs"
      ]
    }
  }
}
```

## Configuration Details

### YAML Configuration Location
The AI enrichment configuration is stored in:
- `~/.llmshield/config.yaml` - User configuration
- `config/ai_enrichment.yaml` - Default enrichment templates

### Available Settings
```yaml
vertex_ai:
  enabled: true              # Enable/disable AI enrichment
  project_id: your-project   # GCP project ID
  location: us-central1      # Vertex AI location
  model_name: gemini-model   # Gemini model to use
  temperature: 0.2           # Model temperature (0-1)
  max_tokens: 2048          # Maximum response length
  timeout: 30               # Request timeout in seconds
```

## Enrichment Types

### 1. Vulnerability Context
Provides detailed explanations of detected vulnerabilities:
- What the vulnerability is
- How it can be exploited
- Real-world attack examples
- Historical incidents

### 2. Risk Assessment
Contextual risk scoring based on:
- Vulnerability severity
- Deployment environment
- Potential impact
- Exploitation difficulty

### 3. Remediation Strategy
Step-by-step guidance:
- Immediate mitigation steps
- Long-term fixes
- Code examples
- Best practices

### 4. Attack Chain Analysis
Maps how vulnerabilities could be chained:
- Entry points
- Exploitation sequences
- Lateral movement possibilities
- Final impact scenarios

## Troubleshooting

### Common Issues

1. **Authentication Error**
   ```
   Error: Could not automatically determine credentials
   ```
   Solution: Run `gcloud auth application-default login`

2. **API Not Enabled**
   ```
   Error: Vertex AI API has not been used in project
   ```
   Solution: Enable the API in GCP Console or run:
   ```bash
   gcloud services enable aiplatform.googleapis.com
   ```

3. **Quota Exceeded**
   ```
   Error: Quota exceeded for gemini requests
   ```
   Solution: Check your GCP quotas or use a different model

### Disabling AI Enrichment

To disable AI enrichment:
1. Use `--no-ai` flag when scanning
2. Or set in config:
   ```yaml
   vertex_ai:
     enabled: false
   ```

## Privacy and Security

- Only vulnerability metadata is sent to AI service
- No actual model weights or sensitive data
- File paths are anonymized
- Responses are cached locally
- All communication uses HTTPS

## Cost Considerations

- Vertex AI charges per 1K characters
- Typical scan: ~$0.01-0.05 per model
- Use caching to reduce costs
- Monitor usage in GCP Console

## Future Enhancements

Currently planned but not yet implemented:
- OpenAI GPT-4 support
- Anthropic Claude support
- Local LLM integration
- Custom prompt templates
- Batch enrichment optimization