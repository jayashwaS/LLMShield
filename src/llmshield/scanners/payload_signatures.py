"""
Payload Signature Database - Known malicious patterns
"""

from typing import Dict, List, Tuple
from .base import Severity


class PayloadSignatures:
    """Database of known malicious payload signatures"""
    
    def __init__(self):
        # Signature format: (pattern, severity, category, description)
        self.signatures: List[Tuple[str, Severity, str, str]] = [
            # Known malicious signatures
            ("EICAR-STANDARD-ANTIVIRUS-TEST-FILE", Severity.CRITICAL, "Known Malware", "EICAR test signature detected"),
            ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", Severity.CRITICAL, "Known Malware", "EICAR test string"),
            ("42eicarboom", Severity.CRITICAL, "Known Malware", "EICAR variant signature"),
            ("mcpotato", Severity.CRITICAL, "Known Malware", "Malicious model identifier"),
            
            # Reverse shells
            ("nc -e /bin/sh", Severity.CRITICAL, "Reverse Shell", "Netcat reverse shell pattern"),
            ("bash -i >& /dev/tcp", Severity.CRITICAL, "Reverse Shell", "Bash reverse shell pattern"),
            ("/bin/bash -c", Severity.HIGH, "Shell Execution", "Direct bash command execution"),
            
            # Data exfiltration patterns
            ("curl.*--data", Severity.HIGH, "Data Exfiltration", "Potential data upload via curl"),
            ("wget.*--post-data", Severity.HIGH, "Data Exfiltration", "Potential data upload via wget"),
            ("requests.post.*data=", Severity.HIGH, "Data Exfiltration", "HTTP POST with data"),
            
            # Cryptomining
            ("stratum+tcp://", Severity.HIGH, "Cryptomining", "Mining pool connection string"),
            ("xmrig", Severity.HIGH, "Cryptomining", "XMRig miner reference"),
            ("minergate", Severity.HIGH, "Cryptomining", "MinerGate reference"),
            
            # Persistence mechanisms  
            ("crontab", Severity.MEDIUM, "Persistence", "Cron job manipulation"),
            (".bashrc", Severity.MEDIUM, "Persistence", "Shell profile modification"),
            ("systemctl", Severity.MEDIUM, "Persistence", "System service manipulation"),
            
            # Information gathering
            ("whoami", Severity.LOW, "Recon", "User enumeration"),
            ("uname -a", Severity.LOW, "Recon", "System information gathering"),
            ("ifconfig", Severity.LOW, "Recon", "Network information gathering"),
            
            # File operations
            ("rm -rf /", Severity.CRITICAL, "Destructive", "Dangerous file deletion"),
            ("dd if=/dev/zero", Severity.CRITICAL, "Destructive", "Disk wiping pattern"),
            ("chmod 777", Severity.MEDIUM, "Permission Change", "Overly permissive file access"),
            
            # Known exploit patterns
            ("pickle.loads", Severity.HIGH, "Deserialization", "Unsafe pickle deserialization"),
            ("yaml.load", Severity.HIGH, "Deserialization", "Unsafe YAML deserialization"),
            ("marshal.loads", Severity.HIGH, "Deserialization", "Unsafe marshal deserialization"),
        ]
        
        # Common obfuscation techniques
        self.obfuscation_indicators = [
            "lambda",  # Often used in obfuscated code
            "\\x",     # Hex encoding
            "chr(",    # Character code usage
            "ord(",    # Character to code
            "getattr", # Dynamic attribute access
            "__",      # Dunder method abuse
        ]
        
        # Suspicious string patterns
        self.suspicious_strings = [
            "password",
            "secret",
            "api_key",
            "token",
            "credential",
            "private_key",
            "ssh_key",
        ]
    
    def get_all_signatures(self) -> List[Tuple[str, Severity, str, str]]:
        """Get all payload signatures"""
        return self.signatures
    
    def get_obfuscation_indicators(self) -> List[str]:
        """Get obfuscation indicator patterns"""
        return self.obfuscation_indicators
    
    def get_suspicious_strings(self) -> List[str]:
        """Get suspicious string patterns"""
        return self.suspicious_strings
    
    def add_signature(self, pattern: str, severity: Severity, 
                     category: str, description: str):
        """Add a new signature to the database"""
        self.signatures.append((pattern, severity, category, description))