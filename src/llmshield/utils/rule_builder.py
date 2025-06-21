"""Interactive rule builder to simplify rule creation."""

import re
from typing import List, Dict, Tuple
from dataclasses import dataclass

@dataclass
class RuleTemplate:
    """Simplified rule structure."""
    name: str
    pattern_type: str  # 'exact', 'regex', 'keyword', 'similarity'
    pattern: str
    severity: str
    context_hints: List[str] = None
    exceptions: List[str] = None

class InteractiveRuleBuilder:
    """Build rules interactively with examples."""
    
    def __init__(self):
        self.templates = {
            'secret': self._build_secret_pattern,
            'api_key': self._build_api_key_pattern,
            'password': self._build_password_pattern,
            'private_key': self._build_private_key_pattern,
            'token': self._build_token_pattern
        }
    
    def build_from_example(self, example: str, rule_type: str = None) -> RuleTemplate:
        """Build a rule from an example string."""
        # Auto-detect rule type if not specified
        if not rule_type:
            rule_type = self._detect_rule_type(example)
        
        if rule_type in self.templates:
            return self.templates[rule_type](example)
        else:
            return self._build_generic_pattern(example)
    
    def _detect_rule_type(self, example: str) -> str:
        """Detect the type of secret from the example."""
        lower_example = example.lower()
        
        if 'api' in lower_example and 'key' in lower_example:
            return 'api_key'
        elif 'password' in lower_example or 'passwd' in lower_example:
            return 'password'
        elif 'private key' in lower_example:
            return 'private_key'
        elif 'token' in lower_example:
            return 'token'
        else:
            return 'secret'
    
    def _build_api_key_pattern(self, example: str) -> RuleTemplate:
        """Build API key pattern from example."""
        # Extract the key part
        match = re.search(r'["\']?([A-Za-z0-9_\-]{20,})["\']?', example)
        if match:
            key = match.group(1)
            # Determine key characteristics
            prefix = self._extract_prefix(key)
            length = len(key)
            
            if prefix:
                pattern = f"{prefix}[A-Za-z0-9_\\-]{{{length-len(prefix)}}}"
            else:
                pattern = f"[A-Za-z0-9_\\-]{{{length-5},{length+5}}}"
            
            return RuleTemplate(
                name=f"API Key ({prefix or 'Generic'})",
                pattern_type='regex',
                pattern=pattern,
                severity='HIGH',
                context_hints=['api', 'key', 'token'],
                exceptions=['example', 'placeholder', 'xxx']
            )
    
    def _extract_prefix(self, key: str) -> str:
        """Extract common prefixes from keys."""
        # Common API key prefixes
        prefixes = ['sk-', 'pk-', 'AKIA', 'AIza', 'ghp_', 'gho_', 'github_pat_']
        
        for prefix in prefixes:
            if key.startswith(prefix):
                return prefix
        
        # Check for custom prefix (uppercase letters followed by underscore)
        match = re.match(r'^([A-Z]+_)', key)
        if match:
            return match.group(1)
        
        return ""
    
    def test_rule(self, rule: RuleTemplate, test_strings: List[str]) -> List[Tuple[str, bool]]:
        """Test a rule against sample strings."""
        results = []
        
        if rule.pattern_type == 'regex':
            pattern = re.compile(rule.pattern)
            for test_str in test_strings:
                match = pattern.search(test_str)
                should_match = not any(exc in test_str.lower() for exc in (rule.exceptions or []))
                results.append((test_str, bool(match) and should_match))
        
        return results
    
    def suggest_improvements(self, rule: RuleTemplate, false_positives: List[str], false_negatives: List[str]) -> RuleTemplate:
        """Improve rule based on false positives and negatives."""
        # Add exceptions for false positives
        new_exceptions = rule.exceptions or []
        for fp in false_positives:
            # Extract the part that shouldn't match
            words = re.findall(r'\w+', fp.lower())
            new_exceptions.extend([w for w in words if len(w) > 3])
        
        rule.exceptions = list(set(new_exceptions))
        
        # Adjust pattern for false negatives
        # This is simplified - in reality would be more sophisticated
        if false_negatives and rule.pattern_type == 'regex':
            # Make pattern more flexible
            rule.pattern = rule.pattern.replace('{', '{0,').replace('}', '}')
        
        return rule

# Example usage
if __name__ == "__main__":
    builder = InteractiveRuleBuilder()
    
    # Build rule from example
    example = "api_key = 'sk-1234567890abcdefghij'"
    rule = builder.build_from_example(example)
    print(f"Generated rule: {rule}")
    
    # Test the rule
    test_cases = [
        "api_key = 'sk-0987654321zyxwvutsr'",  # Should match
        "api_key = 'example-key'",              # Should not match
        "api_key = os.environ['KEY']"          # Should not match
    ]
    
    results = builder.test_rule(rule, test_cases)
    for test_str, matched in results:
        print(f"  {'✓' if matched else '✗'} {test_str}")