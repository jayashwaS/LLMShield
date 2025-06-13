#!/usr/bin/env python3
"""
Example of using YAML-configured AI enrichment
"""

import sys
import json
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.llmshield.enrichment.yaml_configurable_provider import YamlConfigurableProvider
from src.llmshield.enrichment.base import EnrichmentRequest, EnrichmentType


def example_vulnerability_enrichment():
    """Example: Enrich a vulnerability using YAML config."""
    print("=" * 80)
    print("Example 1: Vulnerability Context Enrichment")
    print("=" * 80)
    
    # Initialize provider with YAML config
    provider = YamlConfigurableProvider(
        config={},  # Provider config will be loaded from YAML
        yaml_config_path='config/ai_enrichment.yaml'
    )
    
    # Create enrichment request
    request = EnrichmentRequest(
        type=EnrichmentType.VULNERABILITY_CONTEXT,
        data={
            'severity': 'critical',
            'category': 'Code Execution',
            'description': 'Pickle arbitrary code execution vulnerability',
            'details': 'Model file uses pickle with REDUCE opcode allowing arbitrary Python execution',
            'cve_id': 'CVE-2019-20907',
            'cwe_id': 'CWE-502'
        },
        context={
            'framework': 'pytorch',
            'environment': 'production',
            'usage': 'customer-facing API',
            'network_exposure': 'internet-facing',
            'data_sensitivity': 'high (PII)'
        }
    )
    
    # Get enrichment
    print("\nSending request to AI with YAML-configured prompts...")
    response = provider.enrich(request)
    
    if not response.error:
        print(f"\n✅ Success! Confidence: {response.confidence:.2f}")
        print(f"Model: {response.model_used}")
        print(f"Tokens: {response.tokens_used}")
        print(f"Time: {response.processing_time:.2f}s")
        print("\nInsights:")
        print(json.dumps(response.insights, indent=2))
    else:
        print(f"\n❌ Error: {response.error}")


def example_risk_assessment():
    """Example: Risk assessment with field profile."""
    print("\n" + "=" * 80)
    print("Example 2: Risk Assessment for Executives")
    print("=" * 80)
    
    provider = YamlConfigurableProvider(
        config={},
        yaml_config_path='config/ai_enrichment.yaml'
    )
    
    # Create request with executive profile
    request = EnrichmentRequest(
        type=EnrichmentType.RISK_ASSESSMENT,
        data={
            'vulnerabilities': [
                {
                    'severity': 'critical',
                    'category': 'Code Execution',
                    'description': 'Arbitrary code execution via pickle'
                },
                {
                    'severity': 'high',
                    'category': 'Data Exfiltration',
                    'description': 'Unauthorized network connections detected'
                }
            ]
        },
        context={
            'environment': 'production',
            'data_sensitivity': 'high (financial records)',
            'user_base': '50,000 enterprise customers',
            'regulations': 'SOC2, PCI-DSS',
            'criticality': 'high',
            'field_profile': 'executive_summary'  # Use executive profile
        }
    )
    
    print("\nUsing 'executive_summary' field profile...")
    response = provider.enrich(request)
    
    if not response.error:
        print(f"\n✅ Success!")
        print("\nExecutive Summary (filtered fields):")
        print(json.dumps(response.insights, indent=2))
    else:
        print(f"\n❌ Error: {response.error}")


def example_custom_prompt():
    """Example: Override prompts at runtime."""
    print("\n" + "=" * 80)
    print("Example 3: Custom Prompt Override")
    print("=" * 80)
    
    # Load YAML config
    import yaml
    with open('config/ai_enrichment.yaml', 'r') as f:
        yaml_config = yaml.safe_load(f)
    
    # Modify the system prompt for this request
    yaml_config['enrichment_types']['remediation_strategy']['system_prompt'] = """
    You are a security engineer at a startup with limited resources.
    Focus on free, open-source solutions and quick wins.
    Prioritize fixes that can be implemented in hours, not days.
    """
    
    # Create provider with modified config
    provider = YamlConfigurableProvider(
        config={'yaml_config': yaml_config},
        yaml_config_path=None  # Don't reload from file
    )
    
    request = EnrichmentRequest(
        type=EnrichmentType.REMEDIATION_STRATEGY,
        data={
            'severity': 'critical',
            'description': 'Unsafe deserialization in model loading',
            'current_remediation': 'None implemented yet'
        },
        context={
            'framework': 'tensorflow',
            'deployment_type': 'kubernetes',
            'cicd_platform': 'github-actions',
            'team_expertise': 'junior'
        }
    )
    
    print("\nUsing custom system prompt for startup context...")
    response = provider.enrich(request)
    
    if not response.error:
        print(f"\n✅ Success!")
        print("\nStartup-Friendly Remediation:")
        print(json.dumps(response.insights, indent=2))
    else:
        print(f"\n❌ Error: {response.error}")


def show_yaml_structure():
    """Show the YAML configuration structure."""
    print("\n" + "=" * 80)
    print("YAML Configuration Structure")
    print("=" * 80)
    
    print("""
The YAML configuration file (config/ai_enrichment.yaml) contains:

1. **Provider Settings**: Configure Vertex AI, Gemini, OpenAI
   - API credentials (can use environment variables)
   - Model selection and parameters
   
2. **Enrichment Types**: Define for each type (vulnerability_context, risk_assessment, etc.)
   - System prompts (AI's role and expertise)
   - Output schemas (required/optional fields, types, constraints)
   - Prompt templates (with variable substitution)
   
3. **Output Formatting**: Control response format
   - JSON strictness, field truncation
   - Metadata inclusion
   
4. **Field Profiles**: Pre-defined field filters
   - executive_summary: High-level business impact
   - security_team: Technical details
   - compliance_report: Regulatory focus
   
5. **Validation Rules**: Ensure response quality
   - Required field enforcement
   - Type validation and coercion
   - Custom regex validators

To customize:
1. Edit config/ai_enrichment.yaml
2. Modify system prompts for your use case
3. Define custom output schemas
4. Create new field profiles
5. Set environment variables for API keys
""")


if __name__ == "__main__":
    # Show configuration structure
    show_yaml_structure()
    
    # Run examples
    print("\nRunning examples...")
    
    try:
        example_vulnerability_enrichment()
        example_risk_assessment()
        example_custom_prompt()
    except Exception as e:
        print(f"\nExample failed: {e}")
        print("\nMake sure you have:")
        print("1. config/ai_enrichment.yaml file")
        print("2. Google Cloud authentication set up")
        print("3. Access to the Vertex AI project")