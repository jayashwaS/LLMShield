"""Base classes for AI enrichment providers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Any, List, Optional


class EnrichmentType(Enum):
    """Types of AI enrichment available."""
    VULNERABILITY_CONTEXT = "vulnerability_context"
    CODE_INTENT = "code_intent"
    THREAT_INTELLIGENCE = "threat_intelligence"
    RISK_ASSESSMENT = "risk_assessment"
    REMEDIATION_STRATEGY = "remediation_strategy"
    BEHAVIOR_PREDICTION = "behavior_prediction"
    COMPLIANCE_ANALYSIS = "compliance_analysis"
    ATTACK_CHAIN = "attack_chain"


@dataclass
class EnrichmentRequest:
    """Request for AI enrichment."""
    type: EnrichmentType
    data: Dict[str, Any]
    context: Optional[Dict[str, Any]] = None
    options: Optional[Dict[str, Any]] = None


@dataclass
class EnrichmentResponse:
    """Response from AI enrichment."""
    type: EnrichmentType
    insights: Dict[str, Any]
    confidence: float  # 0.0 to 1.0
    model_used: str
    tokens_used: Optional[int] = None
    processing_time: Optional[float] = None
    error: Optional[str] = None


class BaseEnrichmentProvider(ABC):
    """Abstract base class for AI enrichment providers."""
    
    def __init__(self, api_key: str = None, config: Dict[str, Any] = None):
        """Initialize enrichment provider."""
        self.api_key = api_key
        self.config = config or {}
        self._initialize()
    
    @abstractmethod
    def _initialize(self):
        """Initialize the AI provider connection."""
        pass
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name."""
        pass
    
    @property
    @abstractmethod
    def supported_types(self) -> List[EnrichmentType]:
        """List of supported enrichment types."""
        pass
    
    @abstractmethod
    def enrich(self, request: EnrichmentRequest) -> EnrichmentResponse:
        """Perform AI enrichment."""
        pass
    
    def can_handle(self, enrichment_type: EnrichmentType) -> bool:
        """Check if provider can handle this enrichment type."""
        return enrichment_type in self.supported_types
    
    def _build_prompt(self, request: EnrichmentRequest) -> str:
        """Build prompt for the AI model."""
        prompt_templates = {
            EnrichmentType.VULNERABILITY_CONTEXT: self._vulnerability_context_prompt,
            EnrichmentType.CODE_INTENT: self._code_intent_prompt,
            EnrichmentType.THREAT_INTELLIGENCE: self._threat_intelligence_prompt,
            EnrichmentType.RISK_ASSESSMENT: self._risk_assessment_prompt,
            EnrichmentType.REMEDIATION_STRATEGY: self._remediation_strategy_prompt,
            EnrichmentType.BEHAVIOR_PREDICTION: self._behavior_prediction_prompt,
            EnrichmentType.COMPLIANCE_ANALYSIS: self._compliance_analysis_prompt,
            EnrichmentType.ATTACK_CHAIN: self._attack_chain_prompt,
        }
        
        builder = prompt_templates.get(request.type)
        if builder:
            return builder(request.data, request.context)
        else:
            raise ValueError(f"Unsupported enrichment type: {request.type}")
    
    def _vulnerability_context_prompt(self, data: Dict, context: Dict) -> str:
        """Build prompt for vulnerability context enrichment."""
        return f"""As a cybersecurity expert specializing in ML model security, analyze this vulnerability:

Vulnerability Type: {data.get('severity', 'Unknown')} - {data.get('category', 'Unknown')}
Description: {data.get('description', 'No description')}
Details: {data.get('details', 'No details')}
Scanner: {data.get('scanner', 'Unknown')}

Context:
- Model Type: {context.get('model_type', 'Unknown')}
- Framework: {context.get('framework', 'Unknown')}
- File Size: {context.get('file_size', 'Unknown')}

Provide:
1. A clear explanation of this vulnerability in the context of ML models
2. Real-world attack scenarios specific to ML pipelines
3. Potential impact on model integrity, data privacy, and system security
4. Historical examples or similar incidents if relevant
5. Risk rating specific to ML deployment environments

Format your response as structured insights."""
    
    def _code_intent_prompt(self, data: Dict, context: Dict) -> str:
        """Build prompt for code intent analysis."""
        return f"""Analyze this code found embedded in an ML model file:

```python
{data.get('code', 'No code provided')}
```

Context:
- Found in: {context.get('location', 'Unknown location')}
- Model Framework: {context.get('framework', 'Unknown')}
- Surrounding Context: {context.get('surrounding_context', 'None')}

Determine:
1. The likely purpose and intent of this code
2. Whether this appears malicious or legitimate (with confidence level)
3. Expected behavior when executed
4. Any hidden or obfuscated functionality
5. Potential security implications

Be specific about indicators of malicious intent."""
    
    def _threat_intelligence_prompt(self, data: Dict, context: Dict) -> str:
        """Build prompt for threat intelligence correlation."""
        return f"""Correlate these ML model security findings with known threats:

Findings:
{self._format_findings(data.get('findings', []))}

Model Information:
- Source: {context.get('source', 'Unknown')}
- Hash: {context.get('hash', 'Unknown')}
- Name: {context.get('name', 'Unknown')}

Provide threat intelligence insights:
1. Similarity to known malware families or campaigns
2. Potential attribution or threat actor association
3. Timeline of similar attacks on ML models
4. Indicators of Compromise (IoCs) that match known threats
5. Broader campaign context if applicable"""
    
    def _risk_assessment_prompt(self, data: Dict, context: Dict) -> str:
        """Build prompt for contextual risk assessment."""
        return f"""Perform a comprehensive risk assessment for this ML model:

Vulnerabilities Found:
{self._format_vulnerabilities(data.get('vulnerabilities', []))}

Deployment Context:
- Environment: {context.get('environment', 'Unknown')}
- Usage: {context.get('usage', 'Unknown')}
- Data Sensitivity: {context.get('data_sensitivity', 'Unknown')}
- Network Exposure: {context.get('network_exposure', 'Unknown')}

Provide:
1. Contextual risk score (0-100) with justification
2. Risk factors analysis considering the ML pipeline
3. Compound vulnerability assessment (how vulnerabilities interact)
4. Environmental risk multipliers
5. Likelihood vs Impact matrix for ML-specific threats"""
    
    def _remediation_strategy_prompt(self, data: Dict, context: Dict) -> str:
        """Build prompt for remediation strategy."""
        return f"""Create a remediation strategy for these ML model vulnerabilities:

Vulnerabilities:
{self._format_vulnerabilities(data.get('vulnerabilities', []))}

Constraints:
- Framework: {context.get('framework', 'Any')}
- Production Status: {context.get('production', 'Unknown')}
- Team Expertise: {context.get('expertise', 'Unknown')}
- Timeline: {context.get('timeline', 'ASAP')}

Provide:
1. Prioritized remediation steps with effort estimates
2. Alternative safe implementations for vulnerable patterns
3. Immediate mitigation strategies while fixing
4. Testing recommendations to verify fixes
5. Long-term security improvements for ML pipeline"""
    
    def _behavior_prediction_prompt(self, data: Dict, context: Dict) -> str:
        """Build prompt for behavior prediction."""
        return f"""Predict potential behaviors of this ML model based on security findings:

Security Findings:
{self._format_findings(data.get('findings', []))}

Model Architecture:
- Type: {context.get('model_type', 'Unknown')}
- Layers: {context.get('layers', 'Unknown')}
- Parameters: {context.get('parameters', 'Unknown')}

Predict:
1. Normal operation behavior
2. Potential malicious behaviors and trigger conditions
3. Data flow and exfiltration possibilities
4. Side-channel attack vectors
5. Behavioral indicators to monitor during runtime"""
    
    def _compliance_analysis_prompt(self, data: Dict, context: Dict) -> str:
        """Build prompt for compliance analysis."""
        return f"""Analyze compliance implications of these ML model security findings:

Security Findings:
{self._format_findings(data.get('findings', []))}

Compliance Context:
- Industry: {context.get('industry', 'General')}
- Region: {context.get('region', 'Global')}
- Data Types: {context.get('data_types', 'Unknown')}
- Regulations: {context.get('regulations', 'All applicable')}

Identify:
1. Specific compliance violations
2. Regulatory notification requirements
3. Audit implications
4. Required documentation
5. Remediation timeline per regulations"""
    
    def _attack_chain_prompt(self, data: Dict, context: Dict) -> str:
        """Build prompt for attack chain analysis."""
        return f"""Map potential attack chains using these ML model vulnerabilities:

Vulnerabilities:
{self._format_vulnerabilities(data.get('vulnerabilities', []))}

Environment:
- Deployment: {context.get('deployment', 'Unknown')}
- Network Access: {context.get('network', 'Unknown')}
- Privileges: {context.get('privileges', 'Unknown')}

Create:
1. Step-by-step attack scenarios
2. Exploitation sequence with success likelihood
3. Lateral movement possibilities
4. Data exfiltration paths
5. Impact escalation timeline
6. Cyber kill chain mapping for ML attacks"""
    
    def _format_findings(self, findings: List[Dict]) -> str:
        """Format findings for prompt."""
        if not findings:
            return "No findings provided"
        
        formatted = []
        for i, finding in enumerate(findings, 1):
            formatted.append(f"{i}. {finding.get('type', 'Unknown')}: {finding.get('description', 'No description')}")
        
        return "\n".join(formatted)
    
    def _format_vulnerabilities(self, vulnerabilities: List[Dict]) -> str:
        """Format vulnerabilities for prompt."""
        if not vulnerabilities:
            return "No vulnerabilities provided"
        
        formatted = []
        for i, vuln in enumerate(vulnerabilities, 1):
            formatted.append(
                f"{i}. [{vuln.get('severity', 'Unknown')}] {vuln.get('category', 'Unknown')}: "
                f"{vuln.get('description', 'No description')}"
            )
        
        return "\n".join(formatted)