"""YAML-configurable AI enrichment provider."""

import os
import json
import yaml
import re
from typing import Dict, Any, List, Optional
from pathlib import Path
from string import Template

from .genai_vertex_provider import GenAIVertexProvider
from .base import EnrichmentRequest, EnrichmentResponse, EnrichmentType
from ..core.logger import get_logger

logger = get_logger(__name__)


class YamlConfigurableProvider(GenAIVertexProvider):
    """AI provider that loads configuration from YAML files."""
    
    def __init__(self, config: Dict[str, Any], yaml_config_path: str = None):
        """Initialize with YAML configuration."""
        # Load YAML config first
        self.yaml_config = self._load_yaml_config(yaml_config_path)
        
        # Merge provider settings from YAML
        if self.yaml_config:
            provider_config = self._get_provider_config()
            config.update(provider_config)
        
        super().__init__(config)
        
    def _load_yaml_config(self, yaml_path: str = None) -> Dict[str, Any]:
        """Load YAML configuration file."""
        if not yaml_path:
            # Try default locations
            default_paths = [
                'config/ai_enrichment.yaml',
                'ai_enrichment.yaml',
                os.path.expanduser('~/.llmshield/ai_enrichment.yaml')
            ]
            for path in default_paths:
                if os.path.exists(path):
                    yaml_path = path
                    break
        
        if yaml_path and os.path.exists(yaml_path):
            logger.info(f"Loading AI configuration from {yaml_path}")
            with open(yaml_path, 'r') as f:
                config = yaml.safe_load(f)
                # Process environment variables
                return self._process_env_vars(config)
        
        logger.warning("No AI enrichment YAML config found, using defaults")
        return {}
    
    def _process_env_vars(self, config: Any) -> Any:
        """Replace environment variable placeholders in config."""
        if isinstance(config, dict):
            return {k: self._process_env_vars(v) for k, v in config.items()}
        elif isinstance(config, list):
            return [self._process_env_vars(item) for item in config]
        elif isinstance(config, str):
            # Match ${VAR_NAME:-default_value} pattern
            pattern = r'\$\{([^:}]+)(?::-([^}]+))?\}'
            
            def replacer(match):
                var_name = match.group(1)
                default_value = match.group(2) or ''
                return os.environ.get(var_name, default_value)
            
            return re.sub(pattern, replacer, config)
        else:
            return config
    
    def _get_provider_config(self) -> Dict[str, Any]:
        """Extract provider-specific config from YAML."""
        providers = self.yaml_config.get('providers', {})
        vertex_config = providers.get('vertex', {})
        
        return {
            'project_id': vertex_config.get('project_id'),
            'location': vertex_config.get('location'),
            'model_name': vertex_config.get('model'),
            'temperature': vertex_config.get('temperature', 0.2),
            'max_tokens': vertex_config.get('max_tokens', 8192),
            'top_p': vertex_config.get('top_p', 0.8),
            'top_k': vertex_config.get('top_k', 40)
        }
    
    def _get_enrichment_config(self, enrichment_type: EnrichmentType) -> Dict[str, Any]:
        """Get configuration for specific enrichment type."""
        enrichment_configs = self.yaml_config.get('enrichment_types', {})
        type_key = enrichment_type.value
        return enrichment_configs.get(type_key, {})
    
    def _build_system_prompt(self, enrichment_type: EnrichmentType) -> str:
        """Build system prompt from YAML config."""
        config = self._get_enrichment_config(enrichment_type)
        system_prompt = config.get('system_prompt')
        
        if system_prompt:
            return system_prompt.strip()
        
        # Fall back to parent class default
        return super()._build_system_prompt(enrichment_type)
    
    def _build_user_prompt(self, request: EnrichmentRequest) -> str:
        """Build user prompt using template from YAML."""
        config = self._get_enrichment_config(request.type)
        prompt_template = config.get('prompt_template')
        
        if not prompt_template:
            # Fall back to default prompt building
            return super()._build_prompt(request)
        
        # Prepare template variables
        template_vars = {
            'severity': request.data.get('severity', 'unknown'),
            'category': request.data.get('category', 'unknown'),
            'description': request.data.get('description', ''),
            'details': request.data.get('details', ''),
            'cve_id': request.data.get('cve_id'),
            'cwe_id': request.data.get('cwe_id'),
            'framework': request.context.get('framework', 'unknown'),
            'environment': request.context.get('environment', 'unknown'),
            'usage': request.context.get('usage', 'unknown'),
            'network_exposure': request.context.get('network_exposure', 'unknown'),
            'data_sensitivity': request.context.get('data_sensitivity')
        }
        
        # Handle vulnerability lists for risk assessment
        if 'vulnerabilities' in request.data:
            template_vars['vulnerabilities'] = request.data['vulnerabilities']
        
        # Render template (simple variable substitution)
        rendered = prompt_template
        for key, value in template_vars.items():
            if value is not None:
                # Handle both {{var}} and {{var|default:"value"}} patterns
                pattern1 = f"{{{{{key}}}}}"
                pattern2 = f"{{{{{key}\\|default:\"[^\"]*\"}}}}"
                
                rendered = rendered.replace(pattern1, str(value))
                rendered = re.sub(pattern2, str(value), rendered)
        
        # Handle remaining defaults
        rendered = re.sub(r'{{[^|]+\|default:"([^"]*)"}}', r'\1', rendered)
        
        # Add output schema instruction
        output_schema = config.get('output_schema')
        if output_schema:
            rendered += f"\n\nProvide your response as a JSON object matching this schema:\n{json.dumps(output_schema, indent=2)}"
        
        # Add formatting rules
        formatting = self.yaml_config.get('output_formatting', {})
        if formatting.get('strict_json'):
            rendered += "\n\nIMPORTANT: Return ONLY valid JSON. No additional text or markdown."
        
        return rendered
    
    def enrich(self, request: EnrichmentRequest) -> EnrichmentResponse:
        """Perform enrichment using YAML configuration."""
        import time
        start_time = time.time()
        
        try:
            # Build prompts from YAML config
            system_prompt = self._build_system_prompt(request.type)
            user_prompt = self._build_user_prompt(request)
            
            # Add any prompt helpers
            helpers = self.yaml_config.get('prompt_helpers', {})
            snippets = helpers.get('snippets', {})
            
            if 'output_format_reminder' in snippets:
                user_prompt += f"\n\n{snippets['output_format_reminder']}"
            
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
            insights = self._parse_and_validate_response(response_text, request)
            
            # Apply field profile if specified
            if 'field_profile' in request.context:
                insights = self._apply_field_profile(insights, request.context['field_profile'])
            
            # Calculate confidence
            confidence = self._calculate_confidence_from_response(insights, request.type)
            
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
    
    def _parse_and_validate_response(self, response_text: str, request: EnrichmentRequest) -> Dict[str, Any]:
        """Parse and validate response against schema."""
        try:
            # Extract JSON from response
            json_start = response_text.find('{')
            json_end = response_text.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                json_str = response_text[json_start:json_end]
                insights = json.loads(json_str)
                
                # Validate against schema if available
                config = self._get_enrichment_config(request.type)
                schema = config.get('output_schema')
                
                if schema:
                    insights = self._validate_against_schema(insights, schema)
                
                return insights
            else:
                logger.warning("No JSON found in response")
                return {"raw_response": response_text}
                
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {e}")
            return {"raw_response": response_text, "parse_error": str(e)}
    
    def _validate_against_schema(self, data: Dict[str, Any], schema: Dict[str, Any]) -> Dict[str, Any]:
        """Basic schema validation and correction."""
        if schema.get('type') != 'object':
            return data
        
        required_fields = schema.get('required', [])
        properties = schema.get('properties', {})
        
        # Add missing required fields
        for field in required_fields:
            if field not in data:
                logger.warning(f"Missing required field: {field}")
                # Add default based on type
                field_schema = properties.get(field, {})
                field_type = field_schema.get('type')
                
                if field_type == 'string':
                    data[field] = ''
                elif field_type == 'integer':
                    data[field] = field_schema.get('minimum', 0)
                elif field_type == 'number':
                    data[field] = 0.0
                elif field_type == 'boolean':
                    data[field] = False
                elif field_type == 'array':
                    data[field] = []
                elif field_type == 'object':
                    data[field] = {}
        
        # Validate and correct field values
        for field, field_schema in properties.items():
            if field in data:
                data[field] = self._validate_field(data[field], field_schema)
        
        return data
    
    def _validate_field(self, value: Any, schema: Dict[str, Any]) -> Any:
        """Validate and correct a single field value."""
        field_type = schema.get('type')
        
        if field_type == 'string':
            if not isinstance(value, str):
                value = str(value)
            
            # Check max length
            max_length = schema.get('maxLength')
            if max_length and len(value) > max_length:
                value = value[:max_length]
            
            # Check enum
            enum_values = schema.get('enum')
            if enum_values and value not in enum_values:
                value = enum_values[0]  # Default to first option
            
            # Check pattern
            pattern = schema.get('pattern')
            if pattern and not re.match(pattern, value):
                logger.warning(f"Value '{value}' doesn't match pattern {pattern}")
        
        elif field_type == 'integer':
            try:
                value = int(value)
                if 'minimum' in schema:
                    value = max(value, schema['minimum'])
                if 'maximum' in schema:
                    value = min(value, schema['maximum'])
            except (ValueError, TypeError):
                value = schema.get('minimum', 0)
        
        elif field_type == 'array':
            if not isinstance(value, list):
                value = [value] if value else []
            
            # Check array constraints
            if 'maxItems' in schema and len(value) > schema['maxItems']:
                value = value[:schema['maxItems']]
            
            if 'minItems' in schema and len(value) < schema['minItems']:
                # Can't add items without knowing what they should be
                logger.warning(f"Array has {len(value)} items, minimum is {schema['minItems']}")
        
        elif field_type == 'object':
            if not isinstance(value, dict):
                value = {}
            
            # Recursively validate object properties
            if 'properties' in schema:
                for prop, prop_schema in schema['properties'].items():
                    if prop in value:
                        value[prop] = self._validate_field(value[prop], prop_schema)
        
        return value
    
    def _apply_field_profile(self, insights: Dict[str, Any], profile_name: str) -> Dict[str, Any]:
        """Apply field filtering based on profile."""
        profiles = self.yaml_config.get('field_profiles', {})
        if profile_name not in profiles:
            return insights
        
        profile = profiles[profile_name]
        filtered = {}
        
        # Include specified fields
        include_fields = profile.get('include_fields', [])
        for field in include_fields:
            if field in insights:
                filtered[field] = insights[field]
        
        # Exclude specified fields
        exclude_fields = profile.get('exclude_fields', [])
        for field in exclude_fields:
            filtered.pop(field, None)
        
        # Add profile metadata
        filtered['_profile'] = {
            'name': profile_name,
            'description': profile.get('description', ''),
            'audience': profile.get('additional_context', {}).get('audience', 'general')
        }
        
        return filtered
    
    def _calculate_confidence_from_response(self, insights: Dict[str, Any], enrichment_type: EnrichmentType) -> float:
        """Calculate confidence based on response completeness and quality."""
        if not insights or 'error' in insights:
            return 0.0
        
        # Check if model provided confidence
        if 'confidence_score' in insights:
            try:
                return float(insights['confidence_score'])
            except (ValueError, TypeError):
                pass
        
        # Calculate based on completeness
        config = self._get_enrichment_config(enrichment_type)
        schema = config.get('output_schema', {})
        required_fields = schema.get('required', [])
        
        if required_fields:
            present_count = sum(1 for field in required_fields 
                              if field in insights and insights[field])
            completeness = present_count / len(required_fields)
        else:
            completeness = 0.8
        
        # Boost if no parsing errors
        if 'parse_error' not in insights and 'raw_response' not in insights:
            completeness = min(completeness + 0.1, 0.95)
        
        return completeness