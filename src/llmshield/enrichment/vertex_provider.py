"""Google Vertex AI enrichment provider for Gemini models."""

import json
import time
from typing import List, Dict, Any

from .base import BaseEnrichmentProvider, EnrichmentRequest, EnrichmentResponse, EnrichmentType
from ..core.logger import get_logger

logger = get_logger(__name__)

# Import Vertex AI SDK
try:
    import vertexai
    from vertexai.generative_models import GenerativeModel, GenerationConfig
    VERTEX_AVAILABLE = True
except ImportError:
    VERTEX_AVAILABLE = False
    logger.warning("Vertex AI SDK not installed. Install with: pip install google-cloud-aiplatform")


class VertexProvider(BaseEnrichmentProvider):
    """Google Vertex AI enrichment provider."""
    
    def _initialize(self):
        """Initialize Vertex AI connection."""
        if not VERTEX_AVAILABLE:
            raise ImportError("Vertex AI SDK not installed")
        
        # Get project and location from config
        project_id = self.config.get('project_id', 'dspm-gcp-pm-research')
        location = self.config.get('location', 'global')
        # Support both model_id and model_name for compatibility
        model_id = self.config.get('model_id') or self.config.get('model_name', 'gemini-2.5-pro-preview-06-05')
        
        # Initialize Vertex AI
        vertexai.init(project=project_id, location=location)
        
        # Initialize the model
        self.model = GenerativeModel(model_id)
        
        # Configure generation settings
        self.generation_config = GenerationConfig(
            temperature=self.config.get('temperature', 0.2),
            max_output_tokens=self.config.get('max_tokens', 2048),
            top_p=self.config.get('top_p', 0.8),
            top_k=self.config.get('top_k', 40),
        )
        
        logger.info(f"Initialized Vertex AI provider with model: {model_id} in project: {project_id}")
    
    @property
    def name(self) -> str:
        return "Vertex AI"
    
    @property
    def supported_types(self) -> List[EnrichmentType]:
        """Vertex AI supports all enrichment types."""
        return list(EnrichmentType)
    
    def enrich(self, request: EnrichmentRequest) -> EnrichmentResponse:
        """Perform AI enrichment using Vertex AI."""
        start_time = time.time()
        
        try:
            # Build prompt
            prompt = self._build_prompt(request)
            
            # Add system context
            full_prompt = f"""You are an advanced AI security analyst specializing in machine learning model security.
Your analysis should be precise, actionable, and based on cybersecurity best practices.

{prompt}

Provide your response in JSON format with clear sections for each requested insight."""
            
            # Generate response
            response = self.model.generate_content(
                full_prompt,
                generation_config=self.generation_config
            )
            
            # Extract text from response
            try:
                response_text = response.text
            except Exception as e:
                # Handle case where response is empty or blocked
                if hasattr(response, 'candidates') and response.candidates:
                    candidate = response.candidates[0]
                    if hasattr(candidate, 'finish_reason'):
                        if candidate.finish_reason == 'MAX_TOKENS':
                            logger.warning("Response hit max token limit")
                            # Try to get partial response
                            response_text = "Response truncated due to token limit."
                        elif candidate.finish_reason == 'SAFETY':
                            logger.warning("Response blocked by safety filters")
                            response_text = "Response blocked by safety filters."
                        else:
                            response_text = f"No response text available: {candidate.finish_reason}"
                else:
                    raise e
            
            # Parse response
            insights = self._parse_response(response_text, request.type)
            
            # Calculate confidence based on response
            confidence = self._calculate_confidence(insights, request.type)
            
            # Get token usage if available
            tokens_used = None
            if hasattr(response, 'usage_metadata'):
                tokens_used = response.usage_metadata.total_token_count
            
            return EnrichmentResponse(
                type=request.type,
                insights=insights,
                confidence=confidence,
                model_used=self.config.get('model_id', 'gemini-2.5-pro-preview-06-05'),
                tokens_used=tokens_used,
                processing_time=time.time() - start_time
            )
            
        except Exception as e:
            logger.error(f"Vertex AI enrichment failed: {str(e)}")
            return EnrichmentResponse(
                type=request.type,
                insights={},
                confidence=0.0,
                model_used=self.config.get('model_id', 'gemini-2.5-pro-preview-06-05'),
                processing_time=time.time() - start_time,
                error=str(e)
            )
    
    def _parse_response(self, response_text: str, enrichment_type: EnrichmentType) -> Dict[str, Any]:
        """Parse Vertex AI response into structured insights."""
        try:
            # Try to extract JSON from response
            json_start = response_text.find('{')
            json_end = response_text.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                json_str = response_text[json_start:json_end]
                return json.loads(json_str)
            else:
                # Fall back to structured parsing
                return self._parse_structured_response(response_text, enrichment_type)
                
        except json.JSONDecodeError:
            logger.warning("Failed to parse JSON response, using structured parsing")
            return self._parse_structured_response(response_text, enrichment_type)
    
    def _parse_structured_response(self, response_text: str, enrichment_type: EnrichmentType) -> Dict[str, Any]:
        """Parse non-JSON response into structured format."""
        insights = {}
        
        if enrichment_type == EnrichmentType.VULNERABILITY_CONTEXT:
            insights = {
                "explanation": self._extract_section(response_text, "explanation", "attack"),
                "attack_scenarios": self._extract_section(response_text, "attack", "impact"),
                "impact": self._extract_section(response_text, "impact", "historical"),
                "historical_context": self._extract_section(response_text, "historical", "risk"),
                "risk_rating": self._extract_section(response_text, "risk", None)
            }
        elif enrichment_type == EnrichmentType.CODE_INTENT:
            insights = {
                "purpose": self._extract_section(response_text, "purpose", "malicious"),
                "malicious_assessment": self._extract_section(response_text, "malicious", "behavior"),
                "expected_behavior": self._extract_section(response_text, "behavior", "hidden"),
                "hidden_functionality": self._extract_section(response_text, "hidden", "security"),
                "security_implications": self._extract_section(response_text, "security", None)
            }
        elif enrichment_type == EnrichmentType.RISK_ASSESSMENT:
            insights = {
                "risk_score": self._extract_risk_score(response_text),
                "risk_factors": self._extract_section(response_text, "factors", "compound"),
                "compound_risks": self._extract_section(response_text, "compound", "environmental"),
                "environmental_factors": self._extract_section(response_text, "environmental", "likelihood"),
                "likelihood_impact": self._extract_section(response_text, "likelihood", None)
            }
        else:
            # Generic parsing for other types
            insights = {"raw_insights": response_text}
        
        return insights
    
    def _extract_section(self, text: str, start_marker: str, end_marker: str) -> str:
        """Extract a section of text between markers."""
        import re
        
        if end_marker:
            pattern = rf"(?i){start_marker}.*?:(.*?)(?={end_marker}|$)"
        else:
            pattern = rf"(?i){start_marker}.*?:(.*?)$"
        
        match = re.search(pattern, text, re.DOTALL)
        if match:
            return match.group(1).strip()
        
        return ""
    
    def _extract_risk_score(self, text: str) -> int:
        """Extract risk score from text."""
        import re
        
        # Look for patterns like "risk score: 85" or "85/100"
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
        
        return 50  # Default medium risk
    
    def _calculate_confidence(self, insights: Dict[str, Any], enrichment_type: EnrichmentType) -> float:
        """Calculate confidence score for the insights."""
        if not insights or insights.get('error'):
            return 0.0
        
        # Check completeness of response
        if enrichment_type == EnrichmentType.VULNERABILITY_CONTEXT:
            required_fields = ['explanation', 'attack_scenarios', 'impact']
            present_fields = sum(1 for field in required_fields if insights.get(field))
            return present_fields / len(required_fields)
        
        elif enrichment_type == EnrichmentType.CODE_INTENT:
            # Higher confidence if malicious assessment is definitive
            assessment = insights.get('malicious_assessment', '').lower()
            if 'definitely' in assessment or 'certainly' in assessment:
                return 0.9
            elif 'likely' in assessment or 'probably' in assessment:
                return 0.7
            else:
                return 0.5
        
        elif enrichment_type == EnrichmentType.RISK_ASSESSMENT:
            # Confidence based on presence of risk score and factors
            if insights.get('risk_score') is not None and insights.get('risk_factors'):
                return 0.8
            elif insights.get('risk_score') is not None:
                return 0.6
            else:
                return 0.4
        
        # Default confidence
        return 0.6