# Changelog

All notable changes to LLMShield will be documented in this file.

## [1.0.0] - 2024-12-21

### Added
- Initial release of LLMShield
- Support for 60+ file formats including ML models, source code, and configs
- Dual scanner architecture: PickleScanner and ConfigurableRuleScanner
- YAML-based detection rules for easy customization
- Secret detection for API keys, tokens, and passwords
- Multiple report formats: JSON, HTML, and text
- HuggingFace and Ollama integration
- Directory scanning with recursive support
- AI enrichment with Google Vertex AI (optional)

### Security
- Detection of dangerous pickle opcodes
- Malicious code pattern detection
- EICAR test string detection
- Network exfiltration pattern detection
- Model backdoor signatures

### Features
- Low false positive rate through smart filtering
- Context-aware scanning for different file types
- Enable/disable individual detection rules
- Interactive HTML reports with filtering
- Batch processing for multiple files