"""Customizable prompt templates for AI enrichment."""

from typing import Dict, Any
from .base import EnrichmentType

class PromptTemplates:
    """Centralized prompt templates for AI enrichment."""
    
    # System prompts can be customized per enrichment type
    SYSTEM_PROMPTS = {
        EnrichmentType.VULNERABILITY_CONTEXT: """You are an expert cybersecurity analyst specializing in machine learning model security. Your role is to analyze ML model vulnerabilities and provide deep technical insights about their impact, exploitation methods, and historical context. Always provide accurate, actionable information based on established security principles and real-world attack patterns.""",
        
        EnrichmentType.CODE_INTENT: """You are a malware analyst with expertise in code analysis and reverse engineering. Your task is to analyze code snippets found in ML models to determine their intent, identify malicious patterns, and assess security risks. Be precise in identifying obfuscation techniques, command injection patterns, and data exfiltration methods.""",
        
        EnrichmentType.THREAT_INTELLIGENCE: """You are a threat intelligence analyst specializing in AI/ML attack campaigns. Your role is to correlate security findings with known threat actors, attack campaigns, and emerging ML-specific threats. Provide intelligence based on MITRE ATT&CK framework and real-world incident data.""",
        
        EnrichmentType.RISK_ASSESSMENT: """You are a risk assessment expert for ML systems in production environments. Your task is to evaluate the contextual risk of vulnerabilities considering the deployment environment, data sensitivity, and potential business impact. Provide quantitative risk scores and prioritized recommendations.""",
        
        EnrichmentType.REMEDIATION_STRATEGY: """You are a security engineer specializing in ML model hardening and secure deployment. Your role is to provide detailed, step-by-step remediation strategies that are practical and immediately actionable. Include code examples and configuration changes where applicable.""",
        
        EnrichmentType.BEHAVIOR_PREDICTION: """You are a security researcher focused on ML attack behavior analysis. Your task is to predict how malicious code in ML models might behave during execution, including potential persistence mechanisms, lateral movement, and data exfiltration techniques.""",
        
        EnrichmentType.COMPLIANCE_ANALYSIS: """You are a compliance and regulatory expert for AI/ML systems. Your role is to analyze security findings against regulatory requirements (GDPR, HIPAA, SOC2, etc.) and provide guidance on compliance implications and required notifications.""",
        
        EnrichmentType.ATTACK_CHAIN: """You are a penetration tester specializing in ML infrastructure. Your task is to map out complete attack chains showing how vulnerabilities could be exploited in sequence, including initial access, execution, persistence, and impact stages."""
    }
    
    # Output format specifications - customize the expected JSON structure
    OUTPUT_FORMATS = {
        EnrichmentType.VULNERABILITY_CONTEXT: {
            "template": """Analyze this vulnerability and provide a JSON response with the following structure:
{
    "technical_analysis": "Detailed technical explanation of the vulnerability",
    "exploitation_methods": ["List of specific exploitation techniques"],
    "real_world_impact": {
        "confidentiality": "Impact on data confidentiality",
        "integrity": "Impact on model/system integrity", 
        "availability": "Impact on service availability"
    },
    "attack_scenarios": [
        {
            "name": "Scenario name",
            "description": "Detailed scenario description",
            "likelihood": "high/medium/low",
            "impact": "critical/high/medium/low"
        }
    ],
    "historical_incidents": ["List of similar real-world incidents"],
    "risk_score": 0-100,
    "confidence_level": 0.0-1.0
}""",
            "required_fields": ["technical_analysis", "exploitation_methods", "real_world_impact", "risk_score"],
            "optional_fields": ["attack_scenarios", "historical_incidents", "confidence_level"]
        },
        
        EnrichmentType.RISK_ASSESSMENT: {
            "template": """Perform a contextual risk assessment and provide a JSON response with:
{
    "overall_risk_score": 0-100,
    "risk_matrix": {
        "likelihood": "very_high/high/medium/low/very_low",
        "impact": "catastrophic/major/moderate/minor/insignificant"
    },
    "contributing_factors": [
        {
            "factor": "Factor name",
            "weight": 0.0-1.0,
            "description": "How this factor contributes to risk"
        }
    ],
    "environmental_multipliers": {
        "network_exposure": 1.0-3.0,
        "data_sensitivity": 1.0-3.0,
        "user_base_size": 1.0-3.0
    },
    "business_impact": {
        "financial_loss_estimate": "range or value",
        "reputation_damage": "high/medium/low",
        "regulatory_penalties": "description"
    },
    "priority_recommendation": "immediate/high/medium/low"
}""",
            "required_fields": ["overall_risk_score", "risk_matrix", "priority_recommendation"],
            "optional_fields": ["contributing_factors", "environmental_multipliers", "business_impact"]
        },
        
        EnrichmentType.REMEDIATION_STRATEGY: {
            "template": """Create a remediation strategy and provide a JSON response with:
{
    "immediate_actions": [
        {
            "step": 1,
            "action": "Specific action to take",
            "command": "Exact command or code snippet",
            "estimated_time": "time estimate",
            "risk": "any risks of this action"
        }
    ],
    "short_term_fixes": [
        {
            "fix": "Description of fix",
            "implementation": "How to implement",
            "timeline": "1-7 days",
            "resources_needed": ["list of resources"]
        }
    ],
    "long_term_improvements": [
        {
            "improvement": "Strategic improvement",
            "benefit": "Expected benefit",
            "timeline": "1-6 months"
        }
    ],
    "validation_steps": ["How to verify the fix worked"],
    "rollback_plan": "How to rollback if issues arise"
}""",
            "required_fields": ["immediate_actions", "validation_steps"],
            "optional_fields": ["short_term_fixes", "long_term_improvements", "rollback_plan"]
        }
    }
    
    @classmethod
    def get_system_prompt(cls, enrichment_type: EnrichmentType, custom_prompt: str = None) -> str:
        """Get system prompt for enrichment type, with optional custom override."""
        if custom_prompt:
            return custom_prompt
        return cls.SYSTEM_PROMPTS.get(enrichment_type, "You are an AI security expert.")
    
    @classmethod
    def get_output_format(cls, enrichment_type: EnrichmentType) -> Dict[str, Any]:
        """Get output format specification for enrichment type."""
        return cls.OUTPUT_FORMATS.get(enrichment_type, {
            "template": "Provide a detailed analysis in JSON format.",
            "required_fields": [],
            "optional_fields": []
        })
    
    @classmethod
    def customize_prompt(cls, enrichment_type: EnrichmentType, system_prompt: str = None, 
                        output_format: Dict[str, Any] = None):
        """Customize prompts for a specific enrichment type."""
        if system_prompt:
            cls.SYSTEM_PROMPTS[enrichment_type] = system_prompt
        if output_format:
            cls.OUTPUT_FORMATS[enrichment_type] = output_format
    
    @classmethod
    def build_complete_prompt(cls, enrichment_type: EnrichmentType, 
                             vulnerability_data: Dict[str, Any],
                             context: Dict[str, Any],
                             custom_fields: Dict[str, Any] = None) -> str:
        """Build complete prompt with system prompt and output format."""
        output_spec = cls.get_output_format(enrichment_type)
        
        prompt = f"""Vulnerability Information:
- Severity: {vulnerability_data.get('severity')}
- Category: {vulnerability_data.get('category')}
- Description: {vulnerability_data.get('description')}
- Details: {vulnerability_data.get('details')}
- CVE ID: {vulnerability_data.get('cve_id', 'N/A')}
- CWE ID: {vulnerability_data.get('cwe_id', 'N/A')}

Deployment Context:
- Environment: {context.get('environment', 'unknown')}
- Usage: {context.get('usage', 'unknown')}
- Network Exposure: {context.get('network_exposure', 'unknown')}
- Data Sensitivity: {context.get('data_sensitivity', 'unknown')}
"""
        
        if custom_fields:
            prompt += "\nAdditional Context:\n"
            for key, value in custom_fields.items():
                prompt += f"- {key}: {value}\n"
        
        prompt += f"\n{output_spec.get('template', 'Provide a detailed analysis.')}"
        
        return prompt