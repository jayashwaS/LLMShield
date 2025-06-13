"""Base scanner interface for vulnerability detection."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import List, Dict, Any, Optional


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def score_range(self) -> tuple:
        """Get score range for severity level."""
        ranges = {
            Severity.CRITICAL: (9, 10),
            Severity.HIGH: (7, 8.9),
            Severity.MEDIUM: (4, 6.9),
            Severity.LOW: (1, 3.9),
            Severity.INFO: (0, 0.9)
        }
        return ranges[self]


@dataclass
class Vulnerability:
    """Represents a detected vulnerability."""
    severity: Severity
    category: str
    description: str
    details: str
    remediation: str
    confidence: float = 1.0  # 0.0 to 1.0
    location: Optional[str] = None
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    ai_insights: Optional[Dict[str, Any]] = None  # AI enrichment data
    
    @property
    def risk_score(self) -> float:
        """Calculate risk score based on severity and confidence."""
        severity_scores = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 8,
            Severity.MEDIUM: 5,
            Severity.LOW: 2,
            Severity.INFO: 0.5
        }
        return severity_scores[self.severity] * self.confidence


@dataclass
class ScanResult:
    """Results from a vulnerability scan."""
    scanner_name: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    scan_time: float = 0.0
    file_path: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    
    @property
    def total_vulnerabilities(self) -> int:
        """Get total number of vulnerabilities found."""
        return len(self.vulnerabilities)
    
    @property
    def max_severity(self) -> Optional[Severity]:
        """Get the highest severity level found."""
        if not self.vulnerabilities:
            return None
        return max(self.vulnerabilities, key=lambda v: v.risk_score).severity
    
    @property
    def total_risk_score(self) -> float:
        """Calculate total risk score."""
        return sum(v.risk_score for v in self.vulnerabilities)
    
    def get_by_severity(self, severity: Severity) -> List[Vulnerability]:
        """Get vulnerabilities by severity level."""
        return [v for v in self.vulnerabilities if v.severity == severity]


class BaseScanner(ABC):
    """Abstract base class for vulnerability scanners."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize scanner with optional configuration."""
        self.config = config or {}
        
    @property
    @abstractmethod
    def name(self) -> str:
        """Scanner name."""
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Scanner description."""
        pass
    
    @property
    @abstractmethod
    def supported_formats(self) -> List[str]:
        """List of supported file formats/extensions."""
        pass
    
    @abstractmethod
    def can_scan(self, file_path: Path, parsed_data: Dict[str, Any]) -> bool:
        """Check if this scanner can handle the given file."""
        pass
    
    @abstractmethod
    def scan(self, file_path: Path, parsed_data: Dict[str, Any]) -> ScanResult:
        """Perform vulnerability scan on the file."""
        pass
    
    def _create_vulnerability(
        self,
        vuln_id: str,
        name: str,
        description: str,
        severity: Severity,
        confidence: float = 1.0,
        **kwargs
    ) -> Vulnerability:
        """Helper method to create vulnerability instances."""
        return Vulnerability(
            id=vuln_id,
            name=name,
            description=description,
            severity=severity,
            confidence=confidence,
            **kwargs
        )