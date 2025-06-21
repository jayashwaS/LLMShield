# Custom Rules Guide for LLMShield

This guide explains how to create and use custom detection rules in LLMShield.

## Quick Start

1. **Copy the example file**:
   ```bash
   cp config/custom_rules_example.yaml config/my_custom_rules.yaml
   ```

2. **Edit your custom rules** following the examples provided

3. **Add your rules to the main configuration** by copying them into `detection_rules.yaml`

## Rule Structure

Each rule must have:
- **name**: Human-readable name
- **patterns**: List of regex patterns to match
- **severity**: CRITICAL, HIGH, MEDIUM, or LOW
- **tags**: List of tags for categorization
- **remediation**: Action to take if found

Optional fields:
- **confidence**: 0.0 to 1.0 (default: 0.8)
- **require_context**: Boolean (default: false)
- **min_entropy**: Minimum Shannon entropy
- **exclude_patterns**: Patterns to exclude
- **file_extensions**: Limit to specific extensions
- **file_patterns**: Limit to specific file patterns

## Example: Adding a Company API Key Rule

```yaml
company_secrets:
  mycompany_api_key:
    name: "MyCompany API Key"
    patterns:
      - 'MC_[A-Z0-9]{32}'  # Format: MC_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    severity: "CRITICAL"
    tags: ["company", "api", "secret"]
    remediation: "Remove API key and use environment variables"
    require_context: true  # Must have = or : before it
```

## Testing Your Rules

1. Create a test file with your pattern:
   ```python
   # test_file.py
   api_key = "MC_ABCDEF1234567890ABCDEF1234567890"
   ```

2. Run LLMShield:
   ```bash
   llmshield scan test_file.py
   ```

3. Verify your rule triggers correctly

## Best Practices

1. **Be Specific**: Avoid patterns that match common words
2. **Use Context**: Set `require_context: true` for better accuracy
3. **Test Thoroughly**: Test with both positive and negative cases
4. **Document Well**: Clear names and descriptions help maintenance
5. **Set Appropriate Severity**: Match the actual risk level

## Pattern Writing Tips

### Basic Patterns
- Exact match: `api_key_12345`
- Character class: `[A-Za-z0-9]`
- Repetition: `{32}` for exactly 32, `{16,}` for 16 or more
- Optional: `colou?r` matches "color" or "colour"

### Advanced Patterns
- Lookahead: `(?=...)` - must be followed by
- Lookbehind: `(?<=...)` - must be preceded by
- Negative lookahead: `(?!...)` - must NOT be followed by
- Non-capturing group: `(?:...)` - group without capturing

### Common Use Cases

**API Keys with Context**:
```yaml
patterns:
  - '(?i)api[_-]?key\s*[:=]\s*["\'']([A-Za-z0-9_-]{32,})["\'']'
```

**Excluding Test/Example Keys**:
```yaml
patterns:
  - 'REAL_KEY_[A-Z0-9]{20}'
exclude_patterns:
  - 'REAL_KEY_EXAMPLE'
  - 'REAL_KEY_TEST'
```

**Multi-line Patterns**:
```yaml
patterns:
  - '(?s)BEGIN_SECRET.*?END_SECRET'  # (?s) enables DOTALL mode
```

## Integration Options

### Option 1: Add to Main Config
Copy your tested rules into `detection_rules.yaml`:

```yaml
# In detection_rules.yaml
company_secrets:
  mycompany_api_key:
    name: "MyCompany API Key"
    # ... rest of rule
```

### Option 2: Separate Config File (Future Feature)
In the future, LLMShield may support multiple config files:
```bash
llmshield scan file.py --rules config/detection_rules.yaml,config/my_custom_rules.yaml
```

## Debugging Rules

If your rule isn't working:

1. **Check the regex**: Test on regex101.com
2. **Check the category**: Ensure it's being loaded
3. **Check file exclusions**: Your file might be excluded
4. **Check severity**: Some reports filter by severity
5. **Enable verbose mode**: Use `-v` flag for details

## Common Patterns Library

### Secrets
- AWS Keys: `AKIA[0-9A-Z]{16}`
- GitHub Tokens: `ghp_[A-Za-z0-9_]{36}`
- JWT: `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`

### PII
- SSN: `\d{3}-\d{2}-\d{4}`
- Email: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`
- Phone: `\+?1?\d{10,14}`

### Malware
- Base64 encoded: `[A-Za-z0-9+/]{40,}={0,2}`
- Hex strings: `[0-9a-fA-F]{32,}`
- IP:Port: `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}`

## Need Help?

- Review `custom_rules_example.yaml` for more examples
- Check existing rules in `detection_rules.yaml`
- Test patterns at regex101.com
- File an issue for feature requests