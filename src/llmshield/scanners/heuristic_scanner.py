"""Heuristic-based scanner that uses scoring instead of rigid rules."""

import re
from typing import Dict, List, Any
from dataclasses import dataclass

@dataclass
class HeuristicIndicator:
    """An indicator that contributes to the overall score."""
    name: str
    weight: float
    check_function: callable

class HeuristicScanner:
    """Scanner that uses weighted heuristics instead of rigid rules."""
    
    def __init__(self):
        self.secret_indicators = [
            HeuristicIndicator(
                name="high_entropy",
                weight=0.3,
                check_function=self._has_high_entropy
            ),
            HeuristicIndicator(
                name="secret_keyword",
                weight=0.4,
                check_function=self._has_secret_keyword
            ),
            HeuristicIndicator(
                name="assignment_pattern",
                weight=0.2,
                check_function=self._has_assignment_pattern
            ),
            HeuristicIndicator(
                name="length_check",
                weight=0.1,
                check_function=self._has_secret_length
            ),
            HeuristicIndicator(
                name="no_spaces",
                weight=0.1,
                check_function=self._has_no_spaces
            ),
            HeuristicIndicator(
                name="not_dictionary_word",
                weight=0.2,
                check_function=self._not_dictionary_word
            )
        ]
        
        self.safe_indicators = [
            HeuristicIndicator(
                name="environment_var",
                weight=-0.8,
                check_function=self._uses_env_var
            ),
            HeuristicIndicator(
                name="example_placeholder",
                weight=-0.9,
                check_function=self._is_placeholder
            ),
            HeuristicIndicator(
                name="in_comment",
                weight=-0.7,
                check_function=self._in_comment
            ),
            HeuristicIndicator(
                name="test_file",
                weight=-0.5,
                check_function=self._in_test_file
            )
        ]
    
    def scan_line(self, line: str, context: Dict[str, Any]) -> float:
        """
        Scan a line and return a score from 0 to 1.
        0 = definitely safe
        1 = definitely a secret
        """
        score = 0.0
        
        # Check positive indicators
        for indicator in self.secret_indicators:
            if indicator.check_function(line, context):
                score += indicator.weight
        
        # Check negative indicators (safe patterns)
        for indicator in self.safe_indicators:
            if indicator.check_function(line, context):
                score += indicator.weight  # weight is negative
        
        # Clamp score between 0 and 1
        return max(0.0, min(1.0, score))
    
    def _has_high_entropy(self, line: str, context: Dict) -> bool:
        """Check if line contains high entropy strings."""
        # Extract potential secrets
        matches = re.findall(r'["\']([A-Za-z0-9_\-]{16,})["\']', line)
        for match in matches:
            entropy = self._calculate_entropy(match)
            if entropy > 4.0:
                return True
        return False
    
    def _has_secret_keyword(self, line: str, context: Dict) -> bool:
        """Check for secret-related keywords."""
        keywords = ['key', 'secret', 'token', 'password', 'credential', 'auth']
        line_lower = line.lower()
        return any(kw in line_lower for kw in keywords)
    
    def _has_assignment_pattern(self, line: str, context: Dict) -> bool:
        """Check for variable assignment patterns."""
        patterns = [
            r'\w+\s*=\s*["\'][^"\']+["\']',
            r'\w+\s*:\s*["\'][^"\']+["\']'
        ]
        return any(re.search(p, line) for p in patterns)
    
    def _uses_env_var(self, line: str, context: Dict) -> bool:
        """Check if using environment variables."""
        env_patterns = [
            r'os\.environ',
            r'getenv',
            r'process\.env',
            r'ENV\[',
            r'System\.getenv'
        ]
        return any(re.search(p, line) for p in env_patterns)
    
    def _is_placeholder(self, line: str, context: Dict) -> bool:
        """Check for common placeholder values."""
        placeholders = [
            'your-', 'example', 'placeholder', 'xxx', 
            'todo', 'fixme', 'changeme', 'replace',
            '<', '>'  # <your-key-here>
        ]
        line_lower = line.lower()
        return any(ph in line_lower for ph in placeholders)
    
    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not string:
            return 0.0
        
        char_counts = {}
        for char in string:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        entropy = 0.0
        length = len(string)
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * (probability ** 0.5)  # Simplified
        
        return entropy * 10  # Scale for easier thresholds
    
    def interpret_score(self, score: float) -> Dict[str, Any]:
        """Interpret the heuristic score."""
        if score >= 0.8:
            return {
                'severity': 'CRITICAL',
                'confidence': 'HIGH',
                'description': 'Very likely contains a hardcoded secret'
            }
        elif score >= 0.6:
            return {
                'severity': 'HIGH',
                'confidence': 'MEDIUM',
                'description': 'Likely contains sensitive information'
            }
        elif score >= 0.4:
            return {
                'severity': 'MEDIUM',
                'confidence': 'LOW',
                'description': 'Possibly contains sensitive data'
            }
        else:
            return {
                'severity': 'LOW',
                'confidence': 'VERY_LOW',
                'description': 'Unlikely to be a security issue'
            }

# Example usage
if __name__ == "__main__":
    scanner = HeuristicScanner()
    
    test_cases = [
        ("api_key = 'sk-1234567890abcdef'", {'file': 'main.py'}),
        ("api_key = os.environ.get('API_KEY')", {'file': 'main.py'}),
        ("# Example: api_key = 'your-key-here'", {'file': 'main.py'}),
        ("password = 'mysupersecretpassword123'", {'file': 'config.py'}),
        ("token = 'test-token'", {'file': 'test_auth.py'})
    ]
    
    for line, context in test_cases:
        score = scanner.scan_line(line, context)
        result = scanner.interpret_score(score)
        print(f"Line: {line}")
        print(f"Score: {score:.2f} - {result['description']}")
        print(f"Severity: {result['severity']} (Confidence: {result['confidence']})\n")