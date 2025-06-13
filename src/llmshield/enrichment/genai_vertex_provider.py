"""Google GenAI Vertex AI enrichment provider with system prompts."""

import json
import time
from typing import List, Dict, Any

from .base import BaseEnrichmentProvider, EnrichmentRequest, EnrichmentResponse, EnrichmentType
from ..core.logger import get_logger

logger = get_logger(__name__)

# Import Google GenAI SDK
try:
    from google import genai
    from google.genai import types
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False
    logger.warning("Google GenAI SDK not installed. Install with: pip install google-genai")


class GenAIVertexProvider(BaseEnrichmentProvider):
    """Google GenAI Vertex AI enrichment provider."""
    
    def _initialize(self):
        """Initialize GenAI Vertex AI connection."""
        if not GENAI_AVAILABLE:
            raise ImportError("Google GenAI SDK not installed")
        
        # Get project and location from config
        project_id = self.config.get('project_id', 'dspm-gcp-pm-research')
        location = self.config.get('location', 'global')
        model_id = self.config.get('model_id') or self.config.get('model_name', 'gemini-2.5-pro-preview-06-05')
        
        # Initialize GenAI client
        self.client = genai.Client(
            vertexai=True,
            project=project_id,
            location=location,
        )
        
        self.model_id = model_id
        
        # Configure generation settings
        self.generation_config = types.GenerateContentConfig(
            temperature=self.config.get('temperature', 0.2),
            top_p=self.config.get('top_p', 0.8),
            max_output_tokens=self.config.get('max_tokens', 4096),
            safety_settings=[
                types.SafetySetting(
                    category="HARM_CATEGORY_HATE_SPEECH",
                    threshold="OFF"
                ),
                types.SafetySetting(
                    category="HARM_CATEGORY_DANGEROUS_CONTENT",
                    threshold="OFF"
                ),
                types.SafetySetting(
                    category="HARM_CATEGORY_SEXUALLY_EXPLICIT",
                    threshold="OFF"
                ),
                types.SafetySetting(
                    category="HARM_CATEGORY_HARASSMENT",
                    threshold="OFF"
                )
            ],
        )
        
        logger.info(f"Initialized GenAI Vertex provider with model: {model_id} in project: {project_id}")
    
    @property
    def name(self) -> str:
        return "GenAI Vertex"
    
    @property
    def supported_types(self) -> List[EnrichmentType]:
        """GenAI Vertex supports all enrichment types."""
        return list(EnrichmentType)
    
    def enrich(self, request: EnrichmentRequest) -> EnrichmentResponse:
        """Perform AI enrichment using GenAI Vertex."""
        start_time = time.time()
        
        try:
            # Build system prompt
            system_prompt = self._build_system_prompt(request.type)
            
            # Build user prompt
            user_prompt = self._build_prompt(request)
            
            # Create contents with system and user prompts
            contents = [
                types.Content(
                    role="user",
                    parts=[
                        types.Part(text=f"{system_prompt}\n\n{user_prompt}")
                    ]
                )
            ]
            
            # Generate response
            response_text = ""
            tokens_used = 0
            
            for chunk in self.client.models.generate_content_stream(
                model=self.model_id,
                contents=contents,
                config=self.generation_config,
            ):
                if chunk.text:
                    response_text += chunk.text
                if hasattr(chunk, 'usage_metadata'):
                    tokens_used = chunk.usage_metadata.total_token_count
            
            # Parse response
            insights = self._parse_response(response_text, request.type)
            
            # Calculate confidence based on response
            confidence = self._calculate_confidence(insights, request.type)
            
            return EnrichmentResponse(
                type=request.type,
                insights=insights,
                confidence=confidence,
                model_used=self.model_id,
                tokens_used=tokens_used,
                processing_time=time.time() - start_time
            )
            
        except Exception as e:
            logger.error(f"GenAI Vertex enrichment failed: {str(e)}")
            return EnrichmentResponse(
                type=request.type,
                insights={},
                confidence=0.0,
                model_used=self.model_id,
                processing_time=time.time() - start_time,
                error=str(e)
            )
    
    def _build_system_prompt(self, enrichment_type: EnrichmentType) -> str:
        """Build system prompt for specific enrichment type."""
        system_prompts = {
            EnrichmentType.VULNERABILITY_CONTEXT: """You are an expert cybersecurity analyst specializing in machine learning model security. Your role is to analyze ML model vulnerabilities and provide deep technical insights about their impact, exploitation methods, and historical context. Always provide accurate, actionable information based on established security principles and real-world attack patterns.""",
            
            EnrichmentType.CODE_INTENT: """You are a malware analyst with expertise in code analysis and reverse engineering. Your task is to analyze code snippets found in ML models to determine their intent, identify malicious patterns, and assess security risks. Be precise in identifying obfuscation techniques, command injection patterns, and data exfiltration methods.""",
            
            EnrichmentType.THREAT_INTELLIGENCE: """You are a threat intelligence analyst specializing in AI/ML attack campaigns. Your role is to correlate security findings with known threat actors, attack campaigns, and emerging ML-specific threats. Provide intelligence based on MITRE ATT&CK framework and real-world incident data.""",
            
            EnrichmentType.RISK_ASSESSMENT: """You are a risk assessment expert for ML systems in production environments. Your task is to evaluate the contextual risk of vulnerabilities considering the deployment environment, data sensitivity, and potential business impact. Provide quantitative risk scores and prioritized recommendations.""",
            
            EnrichmentType.REMEDIATION_STRATEGY: """You are a security engineer specializing in ML model hardening and secure deployment. Your role is to provide detailed, step-by-step remediation strategies that are practical and immediately actionable. Include code examples and configuration changes where applicable.""",
            
            EnrichmentType.BEHAVIOR_PREDICTION: """You are a security researcher focused on ML attack behavior analysis. Your task is to predict how malicious code in ML models might behave during execution, including potential persistence mechanisms, lateral movement, and data exfiltration techniques.""",
            
            EnrichmentType.COMPLIANCE_ANALYSIS: """You are a compliance and regulatory expert for AI/ML systems. Your role is to analyze security findings against regulatory requirements (GDPR, HIPAA, SOC2, etc.) and provide guidance on compliance implications and required notifications.""",
            
            EnrichmentType.ATTACK_CHAIN: """You are a penetration tester specializing in ML infrastructure. Your task is to map out complete attack chains showing how vulnerabilities could be exploited in sequence, including initial access, execution, persistence, and impact stages."""
        }
        
        return system_prompts.get(enrichment_type, "You are an AI security expert analyzing machine learning model vulnerabilities.")
    
    def _parse_response(self, response_text: str, enrichment_type: EnrichmentType) -> Dict[str, Any]:
        """Parse GenAI response into structured insights."""
        try:
            # Try to extract JSON from response
            json_start = response_text.find('{')
            json_end = response_text.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                json_str = response_text[json_start:json_end]
                return json.loads(json_str)
            else:
                # Return structured response based on type
                return self._structure_response(response_text, enrichment_type)
                
        except json.JSONDecodeError:
            logger.warning("Failed to parse JSON response, structuring response")
            return self._structure_response(response_text, enrichment_type)
    
    def _structure_response(self, response_text: str, enrichment_type: EnrichmentType) -> Dict[str, Any]:
        """Structure non-JSON response into expected format."""
        # Split response into sections
        sections = response_text.split('\n\n')
        
        if enrichment_type == EnrichmentType.VULNERABILITY_CONTEXT:
            return {
                "explanation": sections[0] if sections else response_text,
                "attack_scenarios": sections[1] if len(sections) > 1 else "",
                "impact": sections[2] if len(sections) > 2 else "",
                "historical_context": sections[3] if len(sections) > 3 else "",
                "risk_rating": self._extract_risk_score(response_text)
            }
        elif enrichment_type == EnrichmentType.RISK_ASSESSMENT:
            return {
                "risk_score": self._extract_risk_score(response_text),
                "risk_factors": sections[0] if sections else response_text,
                "compound_risks": sections[1] if len(sections) > 1 else "",
                "environmental_factors": sections[2] if len(sections) > 2 else "",
                "recommendation": sections[3] if len(sections) > 3 else ""
            }
        else:
            return {"insights": response_text}
    
    def _extract_risk_score(self, text: str) -> int:
        """Extract risk score from text."""
        import re
        
        patterns = [
            r"risk\s*score[:\s]*(\d+)",
            r"(\d+)\s*/\s*100",
            r"score[:\s]*(\d+)"
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                try:
                    score = int(match.group(1))
                    if 0 <= score <= 100:
                        return score
                except ValueError:
                    continue
        
        return 75  # Default high risk for security findings
    
    def _calculate_confidence(self, insights: Dict[str, Any], enrichment_type: EnrichmentType) -> float:
        """Calculate confidence score for the insights."""
        if not insights or insights.get('error'):
            return 0.0
        
        # Base confidence on response completeness
        if isinstance(insights, dict):
            non_empty_fields = sum(1 for v in insights.values() if v and str(v).strip())
            total_fields = len(insights)
            return min(non_empty_fields / total_fields if total_fields > 0 else 0.5, 0.95)
        
        return 0.7  # Default confidence