"""Configurable AI enrichment provider with customizable prompts and outputs."""

import json
import yaml
import time
from typing import List, Dict, Any, Optional
from pathlib import Path

from .genai_vertex_provider import GenAIVertexProvider
from .base import EnrichmentRequest, EnrichmentResponse, EnrichmentType
from .prompt_templates import PromptTemplates
from ..core.logger import get_logger

logger = get_logger(__name__)


class ConfigurableEnrichmentProvider(GenAIVertexProvider):
    """AI enrichment provider with configurable prompts and output formats."""
    
    def __init__(self, config: Dict[str, Any], config_file: Optional[str] = None):
        """Initialize with config dict or config file path."""
        super().__init__(config)
        
        # Load enrichment configuration
        self.enrichment_config = {}
        if config_file:
            self.load_config_file(config_file)
        
        # Override with any passed config
        if 'enrichment' in config:
            self.enrichment_config.update(config['enrichment'])
    
    def load_config_file(self, config_file: str):
        """Load enrichment configuration from YAML file."""
        config_path = Path(config_file)
        if config_path.exists():
            with open(config_path, 'r') as f:
                loaded_config = yaml.safe_load(f)
                self.enrichment_config = loaded_config.get('enrichment', {})
                logger.info(f"Loaded enrichment config from {config_file}")
        else:
            logger.warning(f"Config file not found: {config_file}")
    
    def get_custom_system_prompt(self, enrichment_type: EnrichmentType) -> str:
        """Get custom system prompt from config or fall back to default."""
        custom_prompts = self.enrichment_config.get('custom_prompts', {})
        type_key = enrichment_type.value
        
        if type_key in custom_prompts:
            custom_prompt = custom_prompts[type_key].get('system_prompt')
            if custom_prompt:
                logger.debug(f"Using custom system prompt for {type_key}")
                return custom_prompt.strip()
        
        # Fall back to default from templates
        return PromptTemplates.get_system_prompt(enrichment_type)
    
    def get_output_specification(self, enrichment_type: EnrichmentType) -> Dict[str, Any]:
        """Get output field specification from config."""
        custom_prompts = self.enrichment_config.get('custom_prompts', {})
        type_key = enrichment_type.value
        
        if type_key in custom_prompts:
            output_spec = custom_prompts[type_key].get('output_fields', {})
            output_template = custom_prompts[type_key].get('output_template')
            
            return {
                'required_fields': output_spec.get('required', []),
                'optional_fields': output_spec.get('optional', []),
                'custom_fields': output_spec.get('custom', {}),
                'template': output_template
            }
        
        # Fall back to default
        return PromptTemplates.get_output_format(enrichment_type)
    
    def build_custom_prompt(self, request: EnrichmentRequest) -> str:
        """Build prompt with custom fields and formatting."""
        output_spec = self.get_output_specification(request.type)
        
        # Start with base prompt
        prompt = PromptTemplates.build_complete_prompt(
            enrichment_type=request.type,
            vulnerability_data=request.data,
            context=request.context
        )
        
        # Add custom output template if specified
        if output_spec.get('template'):
            prompt = f"{prompt}\n\nPlease structure your response according to this template:\n{output_spec['template']}"
        
        # Add field specifications
        if output_spec.get('custom_fields'):
            prompt += "\n\nField Specifications:"
            for field_name, field_spec in output_spec['custom_fields'].items():
                prompt += f"\n- {field_name}: {field_spec.get('description', '')}"
                if 'type' in field_spec:
                    prompt += f" (type: {field_spec['type']})"
                if 'values' in field_spec:
                    prompt += f" (allowed values: {', '.join(field_spec['values'])})"
        
        # Add output formatting preferences
        formatting = self.enrichment_config.get('output_formatting', {})
        if formatting.get('json_structure') == 'strict':
            prompt += "\n\nIMPORTANT: Return ONLY valid JSON with the specified fields. No additional text."
        
        return prompt
    
    def enrich(self, request: EnrichmentRequest) -> EnrichmentResponse:
        """Perform enrichment with custom configuration."""
        start_time = time.time()
        
        try:
            # Get custom system prompt
            system_prompt = self.get_custom_system_prompt(request.type)
            
            # Build custom user prompt
            user_prompt = self.build_custom_prompt(request)
            
            # Create contents
            from google.genai import types
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
            
            # Parse and validate response
            insights = self._parse_and_validate_response(response_text, request.type)
            
            # Apply field filtering based on profile
            insights = self._apply_field_profile(insights, request)
            
            # Calculate confidence
            confidence = self._calculate_custom_confidence(insights, request.type)
            
            return EnrichmentResponse(
                type=request.type,
                insights=insights,
                confidence=confidence,
                model_used=self.model_id,
                tokens_used=tokens_used,
                processing_time=time.time() - start_time
            )
            
        except Exception as e:
            logger.error(f"Enrichment failed: {str(e)}")
            return EnrichmentResponse(
                type=request.type,
                insights={},
                confidence=0.0,
                model_used=self.model_id,
                processing_time=time.time() - start_time,
                error=str(e)
            )
    
    def _parse_and_validate_response(self, response_text: str, enrichment_type: EnrichmentType) -> Dict[str, Any]:
        """Parse response and validate against output specification."""
        try:
            # Try to extract JSON
            json_start = response_text.find('{')
            json_end = response_text.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                json_str = response_text[json_start:json_end]
                insights = json.loads(json_str)
                
                # Validate required fields
                output_spec = self.get_output_specification(enrichment_type)
                required_fields = output_spec.get('required_fields', [])
                
                missing_fields = [field for field in required_fields if field not in insights]
                if missing_fields:
                    logger.warning(f"Missing required fields: {missing_fields}")
                    # Add empty placeholders for missing fields
                    for field in missing_fields:
                        insights[field] = None
                
                # Validate custom field constraints
                custom_fields = output_spec.get('custom_fields', {})
                for field_name, field_spec in custom_fields.items():
                    if field_name in insights:
                        insights[field_name] = self._validate_field_value(
                            insights[field_name], field_spec
                        )
                
                return insights
            else:
                logger.warning("No JSON found in response, returning raw text")
                return {"raw_response": response_text}
                
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {e}")
            return {"raw_response": response_text, "parse_error": str(e)}
    
    def _validate_field_value(self, value: Any, field_spec: Dict[str, Any]) -> Any:
        """Validate and potentially transform field value based on specification."""
        field_type = field_spec.get('type')
        
        if field_type == 'enum' and 'values' in field_spec:
            if value not in field_spec['values']:
                logger.warning(f"Invalid enum value: {value}, using first allowed value")
                return field_spec['values'][0]
        
        elif field_type == 'integer':
            try:
                value = int(value)
                if 'min' in field_spec:
                    value = max(value, field_spec['min'])
                if 'max' in field_spec:
                    value = min(value, field_spec['max'])
                return value
            except (ValueError, TypeError):
                return field_spec.get('default', 0)
        
        elif field_type == 'string' and 'max_length' in field_spec:
            if isinstance(value, str) and len(value) > field_spec['max_length']:
                return value[:field_spec['max_length']] + "..."
        
        elif field_type == 'array':
            if not isinstance(value, list):
                value = [value] if value else []
            if 'max_items' in field_spec and len(value) > field_spec['max_items']:
                value = value[:field_spec['max_items']]
            return value
        
        return value
    
    def _apply_field_profile(self, insights: Dict[str, Any], request: EnrichmentRequest) -> Dict[str, Any]:
        """Apply field profile filtering based on use case."""
        # Check if a profile is specified in the request context
        profile_name = request.context.get('field_profile')
        if not profile_name:
            return insights
        
        profiles = self.enrichment_config.get('field_profiles', {})
        if profile_name not in profiles:
            return insights
        
        profile = profiles[profile_name]
        filtered_insights = {}
        
        # Include specified fields
        include_fields = profile.get('include_fields', [])
        if include_fields:
            for field in include_fields:
                if field in insights:
                    filtered_insights[field] = insights[field]
        else:
            # If no include list, start with all fields
            filtered_insights = insights.copy()
        
        # Exclude specified fields
        exclude_fields = profile.get('exclude_fields', [])
        for field in exclude_fields:
            filtered_insights.pop(field, None)
        
        # Add any additional context fields
        additional = profile.get('additional_context', {})
        if additional:
            filtered_insights['context'] = additional
        
        return filtered_insights
    
    def _calculate_custom_confidence(self, insights: Dict[str, Any], enrichment_type: EnrichmentType) -> float:
        """Calculate confidence with custom logic."""
        if not insights or insights.get('error'):
            return 0.0
        
        # Get required fields for this type
        output_spec = self.get_output_specification(enrichment_type)
        required_fields = output_spec.get('required_fields', [])
        
        if required_fields:
            # Calculate based on presence of required fields
            present_fields = sum(1 for field in required_fields if field in insights and insights[field])
            base_confidence = present_fields / len(required_fields)
        else:
            base_confidence = 0.7
        
        # Boost confidence if custom validation passed
        if 'parse_error' not in insights:
            base_confidence = min(base_confidence + 0.1, 0.95)
        
        # Check if the model included confidence in response
        if 'confidence_level' in insights:
            try:
                model_confidence = float(insights['confidence_level'])
                # Average with model's self-reported confidence
                return (base_confidence + model_confidence) / 2
            except (ValueError, TypeError):
                pass
        
        return base_confidence