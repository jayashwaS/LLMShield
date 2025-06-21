# Context-Aware Detection System

## Problem with Current Rules
Current regex-based rules don't understand context, leading to false positives:
- `token = "example"` → False positive
- `api_key = get_from_env()` → False positive  
- `# TODO: api_key = 'abc123'` → False positive in comment

## Proposed Solution: Context-Aware Detection

### 1. Code Structure Analysis
```python
class ContextAwareDetector:
    def analyze(self, code: str) -> List[Finding]:
        # Parse code into AST
        tree = ast.parse(code)
        
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                # Check if assignment contains secrets
                if self._is_secret_assignment(node):
                    # Check context
                    if not self._is_safe_context(node):
                        findings.append(self._create_finding(node))
        
        return findings
    
    def _is_safe_context(self, node) -> bool:
        # Check if it's:
        # - In a comment
        # - Loading from environment
        # - In example/test code
        # - Using a secure method
        pass
```

### 2. Pattern Categories with Context

```yaml
context_aware_rules:
  secrets:
    patterns:
      - name: "Hardcoded API Key"
        detect: 'api_key\s*=\s*["\'](.+)["\']'
        
    safe_contexts:
      - pattern: "os.environ"
      - pattern: "getenv"
      - pattern: "config.get"
      - file_patterns: ["*test*.py", "*example*.py"]
      - in_comments: true
      
    unsafe_contexts:
      - pattern: "production"
      - pattern: "deploy"
      - file_patterns: ["*prod*.py", "*main.py"]
```

### 3. Smart Detection Examples

**Won't Flag (Safe Contexts):**
```python
# Example usage
api_key = "your-key-here"  # In comment

# Loading from environment
api_key = os.environ.get('API_KEY')

# In test file (test_api.py)
api_key = "test-key-12345"

# Using secure storage
api_key = keyring.get_password("myapp", "api_key")
```

**Will Flag (Unsafe Contexts):**
```python
# In production code
class ProductionConfig:
    API_KEY = "sk-real-key-12345"  # Hardcoded in prod
    
# Direct assignment
def connect():
    api_key = "actual-secret-key"
    
# In deployment script
PROD_TOKEN = "ghp_realtoken12345"
```

### 4. Benefits
1. **Reduces False Positives**: Understands code context
2. **Smarter Detection**: Knows when something is actually risky
3. **File-Aware**: Different rules for test vs production files
4. **Comment-Aware**: Ignores examples in comments
5. **Method-Aware**: Recognizes secure coding practices