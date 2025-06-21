# Scanner Consolidation Plan

## Current State (11 Scanners)
1. **YamlRuleScanner** - Base YAML rule engine
2. **SecretScanner** - Wrapper around YamlRuleScanner
3. **PyTorchAttributeScanner** - YAML + custom PyTorch logic
4. **PickleScanner** - Hardcoded pickle opcode analysis
5. **PatternScanner** - Uses vulnerability_db.py
6. **CodeScanner** - Hardcoded dangerous code patterns
7. **SignatureScanner** - Uses payload_signatures.py
8. **EntropyScanner** - Mathematical entropy analysis
9. **ExfiltrationScanner** - Hardcoded network patterns
10. **AnomalyScanner** - Structural anomaly detection
11. **Enhanced scanners** - Additional variations

## Target State (3 Core Scanners)

### 1. **RuleBasedScanner** (Replaces 7 scanners)
- Single scanner using enhanced detection_rules.yaml
- Consolidates patterns from:
  - SecretScanner
  - PatternScanner (vulnerability_db.py patterns)
  - CodeScanner (dangerous code patterns)
  - SignatureScanner (payload_signatures.py)
  - ExfiltrationScanner (network patterns)
  - Parts of PyTorchAttributeScanner
- Categories in YAML:
  - secrets (API keys, passwords, tokens)
  - code_execution (eval, exec, imports)
  - malware_signatures (EICAR, known malware)
  - network_exfiltration (curl, wget, sockets)
  - vulnerabilities (CVEs, framework-specific)
  - persistence (crontab, systemctl)
  - obfuscation (base64, encoding)

### 2. **PickleScanner** (Keep as-is)
- Unique capability: Analyzes pickle opcodes
- Cannot be replaced by pattern matching
- Detects pickle-specific vulnerabilities

### 3. **StructuralScanner** (Optional, combines 2 scanners)
- Combines EntropyScanner + AnomalyScanner
- Mathematical analysis (entropy calculation)
- Structural anomaly detection
- Framework-specific attribute validation

## Implementation Steps

### Step 1: Enhance detection_rules.yaml
Add all patterns from:
- vulnerability_db.py (8 CVEs + patterns)
- payload_signatures.py (50+ signatures)
- CodeScanner hardcoded patterns
- ExfiltrationScanner patterns

### Step 2: Create RuleBasedScanner
- Extends YamlRuleScanner functionality
- Single scanner for all pattern-based detection
- Supports all categories from YAML

### Step 3: Update scanner_manager.py
- Initialize only 3 core scanners
- Remove redundant scanners

### Step 4: Remove deprecated files
- pattern_scanner.py
- code_scanner.py
- signature_scanner.py
- secret_scanner.py (becomes a category in RuleBasedScanner)
- exfiltration_scanner.py
- anomaly_scanner.py
- vulnerability_db.py
- payload_signatures.py

## Benefits
1. **Maintainability**: Update patterns in one YAML file
2. **Performance**: 3 scanners instead of 11
3. **No duplicates**: Each pattern defined once
4. **Clear separation**: Pattern matching vs specialized analysis
5. **Extensibility**: Easy to add new rules without code changes