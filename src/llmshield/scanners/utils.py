"""Utility functions for scanners."""

from typing import Dict, Any, Optional
from .base import Vulnerability, Severity


def create_vulnerability(
    id: str,
    name: str,
    severity: Severity,
    description: str,
    file_path: str,
    details: Dict[str, Any],
    remediation: str,
    category: str = "security",
    cve_id: Optional[str] = None,
    cwe_id: Optional[str] = None,
    location: Optional[str] = None
) -> Vulnerability:
    """Create a vulnerability with proper field mapping."""
    # Map details to the expected format
    details_str = "\n".join([f"{k}: {v}" for k, v in details.items()])
    
    return Vulnerability(
        severity=severity,
        category=category,
        description=f"{name}: {description}",
        details=details_str,
        remediation=remediation,
        location=location or file_path,
        cve_id=cve_id,
        cwe_id=cwe_id,
        evidence=details  # Store structured data in evidence
    )