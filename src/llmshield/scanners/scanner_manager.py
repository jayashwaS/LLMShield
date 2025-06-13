"""Scanner manager for coordinating vulnerability scans."""

from pathlib import Path
from typing import List, Dict, Any, Optional, Type

from ..core.logger import get_logger
from .base import BaseScanner, ScanResult, Severity

logger = get_logger(__name__)


class ScannerManager:
    """Manages and coordinates multiple vulnerability scanners."""
    
    def __init__(self):
        """Initialize scanner manager."""
        self._scanners: List[BaseScanner] = []
        self._scanner_registry: Dict[str, Type[BaseScanner]] = {}
        
    def register_scanner(self, scanner_class: Type[BaseScanner]) -> None:
        """Register a scanner class."""
        scanner_name = scanner_class.__name__
        if scanner_name in self._scanner_registry:
            logger.warning(f"Scanner {scanner_name} already registered, overwriting")
        self._scanner_registry[scanner_name] = scanner_class
        logger.debug(f"Registered scanner: {scanner_name}")
        
    def add_scanner(self, scanner: BaseScanner) -> None:
        """Add a scanner instance."""
        self._scanners.append(scanner)
        logger.debug(f"Added scanner: {scanner.name}")
        
    def remove_scanner(self, scanner_name: str) -> bool:
        """Remove a scanner by name."""
        initial_count = len(self._scanners)
        self._scanners = [s for s in self._scanners if s.name != scanner_name]
        removed = len(self._scanners) < initial_count
        if removed:
            logger.debug(f"Removed scanner: {scanner_name}")
        return removed
        
    def get_scanner(self, scanner_name: str) -> Optional[BaseScanner]:
        """Get a scanner by name."""
        for scanner in self._scanners:
            if scanner.name == scanner_name:
                return scanner
        return None
        
    def list_scanners(self) -> List[Dict[str, str]]:
        """List all available scanners."""
        return [
            {
                "name": scanner.name,
                "description": scanner.description,
                "formats": ", ".join(scanner.supported_formats)
            }
            for scanner in self._scanners
        ]
        
    def scan_file(
        self,
        file_path: Path,
        parsed_data: Dict[str, Any],
        scanner_names: Optional[List[str]] = None
    ) -> List[ScanResult]:
        """
        Scan a file with all applicable scanners.
        
        Args:
            file_path: Path to the file to scan
            parsed_data: Pre-parsed data from parsers
            scanner_names: Optional list of specific scanners to use
            
        Returns:
            List of scan results from all applicable scanners
        """
        results = []
        
        # Determine which scanners to use
        scanners_to_use = self._scanners
        if scanner_names:
            # Handle comma-separated scanner names
            all_scanner_names = []
            for name in scanner_names:
                if ',' in name:
                    all_scanner_names.extend(n.strip() for n in name.split(','))
                else:
                    all_scanner_names.append(name.strip())
            
            logger.debug(f"Requested scanners: {all_scanner_names}")
            scanners_to_use = [s for s in self._scanners if s.name in all_scanner_names]
            logger.info(f"Using {len(scanners_to_use)} scanners: {[s.name for s in scanners_to_use]}")
            
        for scanner in scanners_to_use:
            try:
                if scanner.can_scan(file_path, parsed_data):
                    logger.info(f"Running scanner: {scanner.name}")
                    result = scanner.scan(file_path, parsed_data)
                    results.append(result)
                    
                    # Log summary
                    if result.vulnerabilities:
                        logger.warning(
                            f"{scanner.name} found {result.total_vulnerabilities} "
                            f"vulnerabilities (max severity: {result.max_severity.value})"
                        )
                    else:
                        logger.info(f"{scanner.name} found no vulnerabilities")
                else:
                    logger.debug(f"Scanner {scanner.name} cannot handle file {file_path}")
                    
            except Exception as e:
                logger.error(f"Scanner {scanner.name} failed: {str(e)}")
                # Create error result
                error_result = ScanResult(
                    scanner_name=scanner.name,
                    error=str(e)
                )
                results.append(error_result)
                
        return results
        
    def aggregate_results(self, results: List[ScanResult]) -> Dict[str, Any]:
        """
        Aggregate results from multiple scanners.
        
        Args:
            results: List of scan results
            
        Returns:
            Aggregated summary of all results
        """
        total_vulnerabilities = sum(r.total_vulnerabilities for r in results)
        all_vulnerabilities = []
        for result in results:
            all_vulnerabilities.extend(result.vulnerabilities)
            
        # Group by severity
        by_severity = {
            Severity.CRITICAL: [],
            Severity.HIGH: [],
            Severity.MEDIUM: [],
            Severity.LOW: [],
            Severity.INFO: []
        }
        
        for vuln in all_vulnerabilities:
            by_severity[vuln.severity].append(vuln)
            
        # Calculate max severity
        max_severity = None
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            if by_severity[severity]:
                max_severity = severity
                break
                
        return {
            "total_vulnerabilities": total_vulnerabilities,
            "max_severity": max_severity.value if max_severity else None,
            "by_severity": {
                severity.value: len(vulns) for severity, vulns in by_severity.items()
            },
            "scanners_run": len(results),
            "scanners_with_errors": sum(1 for r in results if r.error),
            "total_risk_score": sum(r.total_risk_score for r in results)
        }
        
    def initialize_default_scanners(self, config: Optional[Dict[str, Any]] = None) -> None:
        """Initialize all default scanners."""
        # Import scanners here to avoid circular imports
        from .pickle_scanner import PickleScanner
        from .pattern_scanner import PatternScanner
        from .code_scanner import CodeScanner
        from .signature_scanner import SignatureScanner
        from .anomaly_scanner import AnomalyScanner
        from .exfiltration_scanner import ExfiltrationScanner
        from .entropy_scanner import EntropyScanner
        from .secret_scanner import SecretScanner
        from .pytorch_attribute_scanner import PyTorchAttributeScanner
        
        # Initialize scanners
        scanners = [
            PickleScanner(config),
            PatternScanner(config),
            CodeScanner(),
            SignatureScanner(),
            AnomalyScanner(),
            ExfiltrationScanner(),
            EntropyScanner(),
            SecretScanner(config),  # Now uses config dict
            PyTorchAttributeScanner(config)  # Now uses config dict
        ]
        
        for scanner in scanners:
            self.add_scanner(scanner)
            
        logger.info(f"Initialized {len(scanners)} default scanners")