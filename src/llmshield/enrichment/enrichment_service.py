"""Main enrichment service for coordinating AI insights."""

from typing import Dict, Any, List, Optional
from pathlib import Path
import json

from ..core.logger import get_logger
from ..core.config import ConfigManager
from ..scanners.base import ScanResult, Vulnerability
from .base import EnrichmentType, EnrichmentRequest, EnrichmentResponse, BaseEnrichmentProvider
# from .gemini_provider import GeminiProvider  # Direct Gemini API, not used currently
from .vertex_provider import VertexProvider

logger = get_logger(__name__)


class EnrichmentService:
    """Service for managing AI enrichment of security findings."""
    
    def __init__(self, config: Optional[ConfigManager] = None):
        """Initialize enrichment service."""
        self.config = config or ConfigManager()
        self.providers: Dict[str, BaseEnrichmentProvider] = {}
        self._cache: Dict[str, EnrichmentResponse] = {}
        self._initialize_providers()
    
    def _initialize_providers(self):
        """Initialize configured AI providers."""
        # Check Vertex AI configuration
        vertex_config = self.config.get('vertex_ai', {})
        logger.debug(f"Vertex AI config: {vertex_config}")
        if vertex_config.get('enabled', False):
            try:
                self.providers['vertex'] = VertexProvider(
                    config=vertex_config
                )
                logger.info("Initialized Vertex AI provider")
            except Exception as e:
                logger.error(f"Failed to initialize Vertex AI provider: {e}")
                import traceback
                traceback.print_exc()
        
        # Check OpenAI configuration (future implementation)
        openai_config = self.config.get('openai', {})
        if openai_config.get('api_key'):
            logger.info("OpenAI provider not yet implemented")
            # TODO: Add OpenAI provider when implemented
        
        # Future: Add other providers (Anthropic, local models, etc.)
    
    def enrich_vulnerabilities(
        self,
        vulnerabilities: List[Vulnerability],
        model_context: Dict[str, Any],
        enrichment_types: Optional[List[EnrichmentType]] = None
    ) -> Dict[str, List[EnrichmentResponse]]:
        """
        Enrich a list of vulnerabilities with AI insights.
        
        Args:
            vulnerabilities: List of detected vulnerabilities
            model_context: Context about the scanned model
            enrichment_types: Types of enrichment to perform (default: context only)
            
        Returns:
            Dictionary mapping vulnerability IDs to enrichment responses
        """
        if not self.providers:
            logger.warning("No AI providers configured for enrichment")
            return {}
        
        # Default enrichment types
        if enrichment_types is None:
            enrichment_types = [EnrichmentType.VULNERABILITY_CONTEXT]
        
        enriched_results = {}
        
        for i, vuln in enumerate(vulnerabilities):
            vuln_id = f"vuln_{i}"
            enriched_results[vuln_id] = []
            
            for enrichment_type in enrichment_types:
                # Prepare request
                request = EnrichmentRequest(
                    type=enrichment_type,
                    data={
                        'severity': vuln.severity.value,
                        'category': vuln.category,
                        'description': vuln.description,
                        'details': vuln.details,
                        'remediation': vuln.remediation,
                        'cve_id': vuln.cve_id,
                        'cwe_id': vuln.cwe_id
                    },
                    context=model_context
                )
                
                # Try enrichment with available providers
                response = self._get_enrichment(request)
                if response and not response.error:
                    enriched_results[vuln_id].append(response)
        
        return enriched_results
    
    def enrich_scan_results(
        self,
        scan_results: List[ScanResult],
        model_info: Dict[str, Any],
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Enrich complete scan results with AI insights.
        
        Args:
            scan_results: List of scan results from all scanners
            model_info: Information about the scanned model
            options: Enrichment options
            
        Returns:
            Enriched scan report with AI insights
        """
        options = options or {}
        
        # Collect all vulnerabilities
        all_vulnerabilities = []
        for result in scan_results:
            all_vulnerabilities.extend(result.vulnerabilities)
        
        enriched_report = {
            'model_info': model_info,
            'total_vulnerabilities': len(all_vulnerabilities),
            'ai_insights': {}
        }
        
        # 1. Vulnerability Context Enrichment
        if options.get('enrich_vulnerabilities', True):
            vuln_enrichments = self.enrich_vulnerabilities(
                all_vulnerabilities,
                model_info,
                [EnrichmentType.VULNERABILITY_CONTEXT]
            )
            enriched_report['ai_insights']['vulnerabilities'] = vuln_enrichments
        
        # 2. Overall Risk Assessment
        if options.get('risk_assessment', True) and all_vulnerabilities:
            risk_request = EnrichmentRequest(
                type=EnrichmentType.RISK_ASSESSMENT,
                data={
                    'vulnerabilities': [
                        {
                            'severity': v.severity.value,
                            'category': v.category,
                            'description': v.description
                        }
                        for v in all_vulnerabilities
                    ]
                },
                context={
                    'model_type': model_info.get('framework'),
                    'environment': options.get('environment', 'production'),
                    'usage': options.get('usage', 'inference'),
                    'network_exposure': options.get('network_exposure', 'internal')
                }
            )
            
            risk_response = self._get_enrichment(risk_request)
            if risk_response and not risk_response.error:
                enriched_report['ai_insights']['risk_assessment'] = risk_response
        
        # 3. Attack Chain Analysis
        if options.get('attack_chain', True) and len(all_vulnerabilities) > 1:
            chain_request = EnrichmentRequest(
                type=EnrichmentType.ATTACK_CHAIN,
                data={
                    'vulnerabilities': [
                        {
                            'severity': v.severity.value,
                            'category': v.category,
                            'description': v.description
                        }
                        for v in all_vulnerabilities
                    ]
                },
                context=model_info
            )
            
            chain_response = self._get_enrichment(chain_request)
            if chain_response and not chain_response.error:
                enriched_report['ai_insights']['attack_chain'] = chain_response
        
        # 4. Remediation Strategy
        if options.get('remediation_strategy', True) and all_vulnerabilities:
            remediation_request = EnrichmentRequest(
                type=EnrichmentType.REMEDIATION_STRATEGY,
                data={
                    'vulnerabilities': [
                        {
                            'severity': v.severity.value,
                            'category': v.category,
                            'description': v.description,
                            'remediation': v.remediation
                        }
                        for v in all_vulnerabilities
                    ]
                },
                context={
                    'framework': model_info.get('framework'),
                    'production': options.get('production', True),
                    'timeline': options.get('timeline', 'immediate')
                }
            )
            
            remediation_response = self._get_enrichment(remediation_request)
            if remediation_response and not remediation_response.error:
                enriched_report['ai_insights']['remediation_strategy'] = remediation_response
        
        return enriched_report
    
    def _get_enrichment(self, request: EnrichmentRequest) -> Optional[EnrichmentResponse]:
        """Get enrichment from available providers."""
        # Check cache first
        cache_key = self._get_cache_key(request)
        if cache_key in self._cache:
            logger.debug(f"Using cached enrichment for {request.type}")
            return self._cache[cache_key]
        
        # Try each provider
        for provider_name, provider in self.providers.items():
            if provider.can_handle(request.type):
                try:
                    logger.info(f"Getting {request.type} enrichment from {provider_name}")
                    response = provider.enrich(request)
                    
                    # Cache successful responses
                    if not response.error:
                        self._cache[cache_key] = response
                    
                    return response
                except Exception as e:
                    logger.error(f"Provider {provider_name} failed: {e}")
                    continue
        
        logger.warning(f"No provider available for {request.type}")
        return None
    
    def _get_cache_key(self, request: EnrichmentRequest) -> str:
        """Generate cache key for request."""
        import hashlib
        
        # Create deterministic key from request data
        key_data = {
            'type': request.type.value,
            'data': request.data,
            'context': request.context
        }
        
        key_str = json.dumps(key_data, sort_keys=True)
        return hashlib.md5(key_str.encode()).hexdigest()
    
    def analyze_code_snippet(
        self,
        code: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Optional[EnrichmentResponse]:
        """Analyze a code snippet for malicious intent."""
        request = EnrichmentRequest(
            type=EnrichmentType.CODE_INTENT,
            data={'code': code},
            context=context or {}
        )
        
        return self._get_enrichment(request)
    
    def get_threat_intelligence(
        self,
        findings: List[Dict[str, Any]],
        model_metadata: Dict[str, Any]
    ) -> Optional[EnrichmentResponse]:
        """Get threat intelligence correlation for findings."""
        request = EnrichmentRequest(
            type=EnrichmentType.THREAT_INTELLIGENCE,
            data={'findings': findings},
            context=model_metadata
        )
        
        return self._get_enrichment(request)
    
    def is_available(self) -> bool:
        """Check if enrichment service is available."""
        return len(self.providers) > 0
    
    def get_providers(self) -> List[str]:
        """Get list of available providers."""
        return list(self.providers.keys())
    
    def clear_cache(self):
        """Clear enrichment cache."""
        self._cache.clear()
        logger.info("Cleared enrichment cache")