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
    location: Optional[str] = None,
    line_number: Optional[int] = None,
    evidence: Optional[Dict[str, Any]] = None
) -> Vulnerability:
    """Create a vulnerability with proper field mapping."""
    # Map details to the expected format
    details_str = "\n".join([f"{k}: {v}" for k, v in details.items()])
    
    # Build location string with line number if available
    if line_number:
        location_str = f"{file_path}:{line_number}"
    else:
        location_str = location or file_path
    
    # Merge evidence with details if provided
    final_evidence = evidence or {}
    final_evidence.update(details)
    if line_number:
        final_evidence['line_number'] = line_number
    
    return Vulnerability(
        severity=severity,
        category=category,
        description=f"{name}: {description}",
        details=details_str,
        remediation=remediation,
        location=location_str,
        cve_id=cve_id,
        cwe_id=cwe_id,
        evidence=final_evidence
    )