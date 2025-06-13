"""Main CLI interface for LLMShield."""

import sys
import re
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from llmshield.core.config import ConfigManager
from llmshield.core.logger import get_logger, setup_logger
from llmshield.core.exceptions import LLMShieldError
from llmshield.parsers import ParserManager
from llmshield.scanners import ScannerManager, Severity
from llmshield.reports import ReportManager, ReportFormat

console = Console()
logger = get_logger()


def parse_size(size_str: str) -> int:
    """Parse size string (e.g., '1GB', '500MB') to bytes."""
    size_str = size_str.strip().upper()
    
    # Define size units
    units = {
        'B': 1,
        'KB': 1024,
        'MB': 1024 * 1024,
        'GB': 1024 * 1024 * 1024,
        'TB': 1024 * 1024 * 1024 * 1024
    }
    
    # Extract number and unit
    match = re.match(r'^(\d+(?:\.\d+)?)\s*([A-Z]+)$', size_str)
    if not match:
        raise ValueError(f"Invalid size format: {size_str}. Use format like '1GB', '500MB', '10MB'")
    
    number, unit = match.groups()
    number = float(number)
    
    if unit not in units:
        raise ValueError(f"Unknown size unit: {unit}. Use B, KB, MB, GB, or TB")
    
    return int(number * units[unit])

BANNER = """
╔═══════════════════════════════════════════════════════════╗
║                     LLMShield v0.1.0                      ║
║        AI Model Security Scanner & Vulnerability Detector  ║
╚═══════════════════════════════════════════════════════════╝
"""


@click.group()
@click.option('--config', '-c', type=click.Path(), help='Path to configuration file')
@click.option('--log-level', '-l', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR']), 
              default='INFO', help='Set logging level')
@click.option('--log-file', type=click.Path(), help='Path to log file')
@click.pass_context
def cli(ctx, config, log_level, log_file):
    """LLMShield - AI Model Security Scanner & Vulnerability Detector"""
    # Setup logging
    setup_logger(level=log_level, log_file=log_file)
    
    # Load configuration
    config_path = Path(config) if config else None
    ctx.obj = ConfigManager(config_path)
    
    # Update from environment variables
    ctx.obj.update_from_env()
    
    # Show banner
    console.print(BANNER, style="bold blue")


@cli.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output directory for reports')
@click.option('--format', '-f', multiple=True, 
              type=click.Choice(['json', 'html', 'text', 'sarif']), 
              default=['json', 'html'], help='Report formats')
@click.option('--no-ai', is_flag=True, help='Disable AI-powered insights')
@click.option('--enrich', is_flag=True, help='Enable AI enrichment of vulnerabilities')
@click.option('--ai-provider', type=click.Choice(['vertex', 'openai']), 
              default='vertex', help='AI provider for enrichment')
@click.option('--timeout', '-t', type=int, help='Scan timeout in seconds')
@click.option('--scanners', '-s', multiple=True, help='Specific scanners to use')
@click.option('--recursive', '-r', is_flag=True, help='Recursively scan subdirectories')
@click.option('--extensions', '-e', multiple=True, help='File extensions to scan')
@click.option('--no-report', is_flag=True, help='Skip report generation')
@click.option('--summary-only', is_flag=True, help='Show summary only, no detailed output')
@click.option('--size', type=str, help='Maximum file size to scan (e.g., 1GB, 500MB, 10MB)')
@click.pass_context
def scan(ctx, path, output, format, no_ai, enrich, ai_provider, timeout, scanners, recursive, extensions, no_report, summary_only, size):
    """Scan a model file or directory for vulnerabilities."""
    try:
        from llmshield.cli.scan_directory import scan_directory
        
        logger.info(f"Starting scan of: {path}")
        
        # Default extensions if not provided
        if not extensions:
            extensions = [
                '.pt', '.pth', '.pkl', '.pb', '.h5', '.hdf5', '.keras', '.onnx', 
                '.safetensors', '.bin', '.yaml', '.yml', '.msgpack', '.flax',
                '.gguf', '.ggml', '.q4_0', '.q4_1', '.q5_0', '.q5_1', '.q8_0',
                '.json', '.npy', '.npz', '.joblib', '.jbl', '.ckpt', '.tflite', '.lite'
            ]
        else:
            extensions = list(extensions)
        
        # Default output directory
        if not output:
            output = ctx.obj.get('report.output_dir', 'reports')
        
        # Update config with CLI options
        if timeout:
            ctx.obj.set('scanner.timeout', timeout)
        
        # Enable Vertex AI if enrichment is requested
        if enrich and not no_ai:
            if ai_provider == 'vertex':
                ctx.obj.set('vertex_ai.enabled', True)
                # Configuration should come from YAML or environment variables
        
        # Parse size limit if provided
        max_size_bytes = None
        if size:
            max_size_bytes = parse_size(size)
        
        # Perform scan
        files_scanned, total_vulns, max_severity = scan_directory(
            path=path,
            output=output if not no_report else None,
            formats=list(format),
            recursive=recursive,
            extensions=extensions,
            scanners=list(scanners) if scanners else None,
            config=ctx.obj.config.dict(),
            enrich=enrich and not no_ai,
            ai_provider=ai_provider,
            max_size_bytes=max_size_bytes
        )
        
        # Display final summary
        console.print("\n" + "=" * 60)
        console.print(f"[bold green]Scan Complete![/bold green]")
        console.print(f"  Files Scanned: {files_scanned}")
        console.print(f"  Total Vulnerabilities: {total_vulns}")
        if max_severity:
            console.print(f"  Maximum Severity: [bold red]{max_severity}[/bold red]")
        console.print("=" * 60)
        
        logger.info("Scan completed successfully!")
        
    except LLMShieldError as e:
        logger.error(f"Scan failed: {e}")
        sys.exit(1)
    except Exception as e:
        logger.critical(f"Unexpected error: {e}")
        sys.exit(1)


@cli.command()
@click.argument('model_id')
@click.option('--source', '-s', type=click.Choice(['huggingface', 'ollama']), 
              required=True, help='Model source')
@click.option('--output', '-o', type=click.Path(), help='Output directory')
@click.option('--scan', is_flag=True, help='Scan model after pulling')
@click.option('--skip-safety-check', is_flag=True, help='Skip preliminary safety checks')
@click.pass_context
def pull(ctx, model_id, source, output, scan, skip_safety_check):
    """Pull a model from HuggingFace or Ollama."""
    try:
        from llmshield.integrations import HuggingFaceIntegration, OllamaIntegration
        from llmshield.parsers import ParserManager
        
        logger.info(f"Pulling model '{model_id}' from {source}")
        
        output_path = Path(output) if output else None
        
        if source == 'huggingface':
            integration = HuggingFaceIntegration(ctx.obj.config.huggingface.dict())
            
            # Perform safety check
            if not skip_safety_check:
                logger.progress("Performing preliminary safety check...")
                safety_report = integration.verify_model_safety(model_id)
                
                if not safety_report['checks_passed']:
                    logger.warning("Safety check failed!")
                    for warning in safety_report['warnings']:
                        logger.warning(f"  • {warning}")
                    
                    if not click.confirm("Do you want to continue anyway?"):
                        logger.info("Pull cancelled")
                        return
            
            # Pull the model
            logger.progress(f"Downloading model '{model_id}'...")
            model_dir = integration.pull_model(model_id, output_path)
            
        elif source == 'ollama':
            integration = OllamaIntegration(ctx.obj.config.ollama.dict())
            
            # Check if Ollama is running
            if not integration.check_connection():
                logger.error("Cannot connect to Ollama. Please ensure Ollama is running.")
                sys.exit(1)
            
            # Pull the model
            logger.progress(f"Pulling model '{model_id}' with Ollama...")
            model_dir = integration.pull_model(model_id, output_path)
        
        logger.success(f"Model downloaded to: {model_dir}")
        
        if scan:
            logger.info("Starting automatic scan...")
            
            # Find model files to scan
            parser_manager = ParserManager(ctx.obj.config.dict())
            model_files = []
            
            for file in model_dir.rglob('*'):
                if file.is_file() and parser_manager.is_supported(file):
                    model_files.append(file)
            
            if model_files:
                logger.info(f"Found {len(model_files)} model files to scan")
                # Scan the entire directory
                ctx.invoke(scan, path=str(model_dir), recursive=True)
            else:
                logger.warning("No scannable model files found in download")
            
    except LLMShieldError as e:
        logger.error(f"Pull failed: {e}")
        sys.exit(1)
    except Exception as e:
        logger.critical(f"Unexpected error: {e}")
        sys.exit(1)


@cli.command()
@click.pass_context
def config(ctx):
    """Display current configuration."""
    config_dict = ctx.obj.config.dict()
    
    table = Table(title="LLMShield Configuration", show_header=True)
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="yellow")
    
    def add_config_items(data, prefix=""):
        for key, value in data.items():
            if isinstance(value, dict):
                add_config_items(value, f"{prefix}{key}.")
            else:
                table.add_row(f"{prefix}{key}", str(value))
    
    add_config_items(config_dict)
    console.print(table)


@cli.command()
@click.option('--show-example', is_flag=True, help='Show example configuration')
@click.pass_context
def configure(ctx):
    """Show configuration information."""
    if ctx.params.get('show_example'):
        console.print("\n[bold]Example Configuration:[/bold]")
        console.print("Copy to ~/.llmshield/config.yaml\n")
        
        example = """scanner:
  timeout: 120
  severity_threshold: medium
  
vertex_ai:
  enabled: true
  project_id: your-gcp-project  # or set VERTEX_PROJECT_ID
  location: us-central1         # or set VERTEX_LOCATION
  model_name: gemini-2.0-flash-exp
  
huggingface:
  cache_dir: ~/.llmshield/models/huggingface
  # api_token: hf_...  # or set HF_TOKEN env var"""
        
        console.print(example)
        console.print("\n[bold]Environment Variables:[/bold]")
        console.print("GOOGLE_APPLICATION_CREDENTIALS - GCP credentials path")
        console.print("VERTEX_PROJECT_ID - GCP project ID")
        console.print("VERTEX_LOCATION - GCP region")
        console.print("VERTEX_MODEL - Gemini model name")
        console.print("HF_TOKEN - HuggingFace API token")
    else:
        console.print("\n[bold]Current Configuration:[/bold]")
        console.print(f"Config file: {ctx.obj.config_path}")
        console.print("\nUse 'llmshield config' to view current settings")
        console.print("Use 'llmshield configure --show-example' for example config")


@cli.command()
def version():
    """Display LLMShield version."""
    console.print(Panel.fit(
        "[bold blue]LLMShield[/bold blue] v0.1.0\n"
        "[dim]AI Model Security Scanner & Vulnerability Detector[/dim]",
        title="Version Info",
        border_style="blue"
    ))


@cli.command()
def list_parsers():
    """List supported model formats."""
    formats = [
        ("PyTorch", ".pt, .pth, .bin", "✅"),
        ("TensorFlow", ".pb, .h5, .hdf5, .keras", "✅"),
        ("ONNX", ".onnx", "✅"),
        ("Pickle", ".pkl, .pickle", "✅"),
        ("Safetensors", ".safetensors", "✅"),
        ("YAML/Config", ".yaml, .yml", "✅"),
        ("JAX/Flax", ".msgpack, .flax", "✅"),
        ("GGUF/GGML", ".gguf, .ggml, .q4_0, .q4_1, .q5_0, .q5_1, .q8_0", "✅"),
        ("JSON", ".json", "✅"),
        ("NumPy", ".npy, .npz", "✅"),
        ("Joblib", ".joblib, .jbl", "✅"),
        ("Checkpoint", ".ckpt", "✅"),
        ("TFLite", ".tflite, .lite", "✅"),
    ]
    
    table = Table(title="Supported Model Formats", show_header=True)
    table.add_column("Framework", style="cyan")
    table.add_column("Extensions", style="yellow")
    table.add_column("Status", justify="center")
    
    for fmt in formats:
        table.add_row(*fmt)
    
    console.print(table)
    console.print("\n✅ = Supported, 🚧 = Coming Soon")


def main():
    """Main entry point."""
    try:
        cli()
    except KeyboardInterrupt:
        logger.warning("\nOperation cancelled by user")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()