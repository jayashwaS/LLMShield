"""Directory scanning functionality for LLMShield."""

import os
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

from llmshield.core.logger import get_logger
from llmshield.parsers import ParserManager
from llmshield.scanners import ScannerManager, Severity
from llmshield.reports import ReportManager, ReportFormat

logger = get_logger(__name__)
console = Console()


def collect_model_files(path: Path, extensions: List[str], recursive: bool = False) -> List[Path]:
    """Collect all model files in a directory."""
    model_files = []
    
    if path.is_file():
        # Single file
        if any(str(path).endswith(ext) for ext in extensions):
            model_files.append(path)
    else:
        # Directory
        if recursive:
            for ext in extensions:
                model_files.extend(path.rglob(f"*{ext}"))
        else:
            for ext in extensions:
                model_files.extend(path.glob(f"*{ext}"))
    
    # Sort for consistent ordering
    return sorted(model_files)


def scan_directory(
    path: str,
    output: Optional[str] = None,
    formats: List[str] = ['json', 'html'],
    recursive: bool = False,
    extensions: List[str] = None,
    scanners: Optional[List[str]] = None,
    config: Dict[str, Any] = None,
    enrich: bool = False,
    ai_provider: str = 'vertex',
    max_size_bytes: Optional[int] = None
) -> Tuple[int, int, Optional[str]]:
    """
    Scan a directory or file for model vulnerabilities.
    
    Returns:
        Tuple of (files_scanned, total_vulnerabilities, max_severity)
    """
    if extensions is None:
        extensions = [
            '.pt', '.pth', '.pkl', '.pb', '.h5', '.hdf5', '.keras', '.onnx', 
            '.safetensors', '.bin', '.yaml', '.yml', '.msgpack', '.flax',
            '.gguf', '.ggml', '.q4_0', '.q4_1', '.q5_0', '.q5_1', '.q8_0',
            '.json', '.npy', '.npz', '.joblib', '.jbl', '.ckpt', '.tflite', '.lite'
        ]
    
    path_obj = Path(path)
    
    # Collect files
    model_files = collect_model_files(path_obj, extensions, recursive)
    
    if not model_files:
        logger.warning(f"No model files found in {path} with extensions: {', '.join(extensions)}")
        return 0, 0, None
    
    # Filter files by size if max_size_bytes is specified
    if max_size_bytes:
        filtered_files = []
        skipped_files = []
        
        for file_path in model_files:
            file_size = file_path.stat().st_size
            if file_size <= max_size_bytes:
                filtered_files.append(file_path)
            else:
                skipped_files.append((file_path, file_size))
        
        if skipped_files:
            console.print(f"\n[yellow]Skipping {len(skipped_files)} file(s) larger than {max_size_bytes / (1024**3):.2f}GB:[/yellow]")
            for skip_file, size in skipped_files[:5]:  # Show first 5
                console.print(f"  - {skip_file.name} ({size / (1024**3):.2f}GB)")
            if len(skipped_files) > 5:
                console.print(f"  ... and {len(skipped_files) - 5} more")
        
        model_files = filtered_files
        
        if not model_files:
            logger.warning(f"All files exceeded size limit of {max_size_bytes / (1024**3):.2f}GB")
            return 0, 0, None
    
    logger.info(f"Found {len(model_files)} model file(s) to scan")
    
    # Initialize managers
    parser_manager = ParserManager(config or {})
    scanner_manager = ScannerManager()
    scanner_manager.initialize_default_scanners(config or {})
    report_manager = ReportManager(Path(output) if output else None)
    
    # Track overall results
    all_scan_results = []
    all_vulnerabilities = []
    total_vulnerabilities = 0
    max_severity = None
    files_with_issues = []
    
    # Initialize enrichment service if requested
    enrichment_service = None
    if enrich:
        try:
            from ..enrichment import EnrichmentService
            from ..core.config import ConfigManager
            
            # Create config manager with provided config
            config_manager = ConfigManager()
            if config:
                config_manager.config = config
                
            # Enable AI provider
            if ai_provider == 'vertex':
                config_manager.set('vertex_ai.enabled', True)
                if 'vertex_ai' in config:
                    for key, value in config['vertex_ai'].items():
                        config_manager.set(f'vertex_ai.{key}', value)
            
            enrichment_service = EnrichmentService(config_manager)
            logger.info(f"Initialized AI enrichment with provider: {ai_provider}")
        except Exception as e:
            logger.warning(f"Failed to initialize AI enrichment: {e}")
            enrichment_service = None
    
    # Create summary table
    summary_table = Table(title="Scan Summary", show_header=True)
    summary_table.add_column("File", style="cyan")
    summary_table.add_column("Framework", style="yellow")
    summary_table.add_column("Issues", style="red", justify="right")
    summary_table.add_column("Max Severity", style="magenta")
    summary_table.add_column("Status", style="green")
    
    # Scan each file
    with Progress() as progress:
        scan_task = progress.add_task("[cyan]Scanning files...", total=len(model_files))
        
        for model_path in model_files:
            progress.update(scan_task, description=f"[cyan]Scanning {model_path.name}...")
            
            try:
                # Parse file
                parse_result = parser_manager.parse_file(model_path)
                
                # Convert parse result to dict
                # Use the to_dict method if available
                if hasattr(parse_result, 'to_dict'):
                    parsed_data = parse_result.to_dict()
                else:
                    # Fallback to manual construction
                    parsed_data = {
                        'format': parse_result.metadata.format,
                        'framework': parse_result.metadata.framework,
                        'file_size': parse_result.metadata.file_size,
                        'file_hash': parse_result.metadata.file_hash,
                        'warnings': parse_result.warnings,
                        'suspicious_patterns': parse_result.suspicious_patterns
                    }
                    
                    # Include custom attributes (parsed content) if available
                    if parse_result.metadata.custom_attributes:
                        parsed_data.update(parse_result.metadata.custom_attributes)
                
                # Run scanners
                scan_results = scanner_manager.scan_file(
                    model_path,
                    parsed_data,
                    scanner_names=scanners
                )
                
                # Aggregate results for this file
                aggregated = scanner_manager.aggregate_results(scan_results)
                file_vulns = aggregated['total_vulnerabilities']
                file_severity = aggregated['max_severity']
                
                # Update totals
                total_vulnerabilities += file_vulns
                if file_vulns > 0:
                    files_with_issues.append((model_path, file_vulns, file_severity))
                    
                    # Enrich vulnerabilities if service is available
                    if enrichment_service:
                        try:
                            logger.info(f"Enriching vulnerabilities for {model_path.name}")
                            for scan_result in scan_results:
                                if scan_result.vulnerabilities:
                                    model_context = {
                                        'framework': parse_result.metadata.framework,
                                        'format': parse_result.metadata.format,
                                        'file_size': parse_result.metadata.file_size,
                                        'file_path': str(model_path),
                                        'model_name': model_path.name
                                    }
                                    
                                    enriched = enrichment_service.enrich_vulnerabilities(
                                        vulnerabilities=scan_result.vulnerabilities,
                                        model_context=model_context
                                    )
                                    
                                    # Add enrichment data to vulnerabilities
                                    for vuln in scan_result.vulnerabilities:
                                        if vuln.id in enriched:
                                            vuln.ai_insights = enriched[vuln.id]
                        except Exception as e:
                            logger.warning(f"Failed to enrich vulnerabilities: {e}")
                    
                    all_scan_results.extend(scan_results)
                    
                    # Update max severity
                    if file_severity:
                        if max_severity is None or Severity(file_severity).value > Severity(max_severity).value:
                            max_severity = file_severity
                
                # Add to summary table
                summary_table.add_row(
                    model_path.name,
                    parse_result.metadata.framework,
                    str(file_vulns) if file_vulns > 0 else "0",
                    file_severity or "None",
                    "⚠️  Issues Found" if file_vulns > 0 else "✅ Clean"
                )
                
            except Exception as e:
                logger.error(f"Error scanning {model_path}: {e}")
                summary_table.add_row(
                    model_path.name,
                    "Unknown",
                    "Error",
                    "Error",
                    f"❌ Error: {str(e)[:30]}..."
                )
            
            progress.advance(scan_task)
    
    # Display summary
    console.print("\n")
    console.print(summary_table)
    
    # Display detailed results for files with issues
    if files_with_issues:
        console.print(f"\n[bold red]Found vulnerabilities in {len(files_with_issues)} file(s):[/bold red]\n")
        
        for file_path, vuln_count, severity in files_with_issues:
            console.print(f"[bold yellow]{file_path.name}[/bold yellow] - {vuln_count} issue(s), max severity: {severity}")
    
    # Generate combined report if requested
    if output and all_scan_results:
        logger.info("Generating combined report...")
        report_data = {
            'scan_path': str(path),
            'files_scanned': len(model_files),
            'files_with_issues': len(files_with_issues),
            'total_vulnerabilities': total_vulnerabilities,
            'max_severity': max_severity,
            'scan_results': all_scan_results,
            'file_summaries': [
                {
                    'file': str(f[0]),
                    'vulnerabilities': f[1],
                    'max_severity': f[2]
                }
                for f in files_with_issues
            ]
        }
        
        # Generate reports
        report_formats = [ReportFormat(f) for f in formats]
        report_paths = report_manager.generate_reports(
            model_path=str(path),
            model_info={'scan_type': 'directory', 'files_scanned': len(model_files)},
            scan_results=all_scan_results,
            scan_duration=0.0,  # We don't track duration for now
            formats=report_formats,
            metadata=report_data
        )
        
        if report_paths:
            console.print(f"\n[bold green]Reports saved to:[/bold green] {output}")
            for fmt, path in report_paths.items():
                console.print(f"  - {fmt}: {path}")
    
    return len(model_files), total_vulnerabilities, max_severity