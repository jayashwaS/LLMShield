"""Main CLI interface for LLMShield."""

import sys
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from llmshield.core.config import ConfigManager
from llmshield.core.logger import get_logger, setup_logger
from llmshield.core.exceptions import LLMShieldError

console = Console()
logger = get_logger()

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
@click.argument('model_path', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output directory for reports')
@click.option('--format', '-f', multiple=True, 
              type=click.Choice(['json', 'html', 'text', 'sarif']), 
              default=['json', 'html'], help='Report formats')
@click.option('--no-ai', is_flag=True, help='Disable AI-powered insights')
@click.option('--timeout', '-t', type=int, help='Scan timeout in seconds')
@click.pass_context
def scan(ctx, model_path, output, format, no_ai, timeout):
    """Scan a model file for vulnerabilities."""
    try:
        from llmshield.parsers import ParserManager
        
        logger.info(f"Starting scan of: {model_path}")
        
        # Update config with CLI options
        if output:
            ctx.obj.set('report.output_dir', output)
        if format:
            ctx.obj.set('report.formats', list(format))
        if no_ai:
            ctx.obj.set('report.include_ai_insights', False)
        if timeout:
            ctx.obj.set('scanner.timeout', timeout)
        
        # Initialize parser manager
        parser_manager = ParserManager(ctx.obj.config.dict())
        
        # Parse the model file
        logger.scan("Scanning model for vulnerabilities...")
        logger.progress("Analyzing model structure...")
        
        result = parser_manager.parse_file(Path(model_path))
        
        # Display results
        console.print("\n[bold green]Parse Results:[/bold green]")
        console.print(f"  Framework: {result.metadata.framework}")
        console.print(f"  Format: {result.metadata.format}")
        console.print(f"  File Size: {result.metadata.file_size:,} bytes")
        console.print(f"  File Hash: {result.metadata.file_hash[:16]}...")
        
        if result.metadata.parameters_count:
            console.print(f"  Parameters: {result.metadata.parameters_count:,}")
        
        if result.warnings:
            console.print("\n[bold yellow]Warnings:[/bold yellow]")
            for warning in result.warnings:
                logger.warning(f"  • {warning}")
        
        if result.suspicious_patterns:
            console.print("\n[bold red]Suspicious Patterns:[/bold red]")
            for pattern in result.suspicious_patterns:
                logger.vulnerability(f"  • {pattern}", severity="high")
        
        if result.embedded_code:
            console.print("\n[bold red]Embedded Code Detected:[/bold red]")
            for code in result.embedded_code:
                logger.vulnerability(f"  • {code.get('type', 'unknown')}: {code.get('risk', 'unknown')} risk", severity="high")
        
        if not result.warnings and not result.suspicious_patterns and not result.embedded_code:
            logger.safe("No security issues detected")
        
        logger.success("Scan completed successfully!")
        
        console.print(f"\n[bold green]Scan Summary:[/bold green]")
        console.print(f"  Model: {model_path}")
        console.print(f"  Status: [yellow]{len(result.warnings)} warnings, {len(result.suspicious_patterns)} suspicious patterns[/yellow]")
        console.print(f"  Reports saved to: {ctx.obj.get('report.output_dir')}")
        
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
@click.option('--scan-after-pull', is_flag=True, help='Scan model after pulling')
@click.option('--skip-safety-check', is_flag=True, help='Skip preliminary safety checks')
@click.pass_context
def pull(ctx, model_id, source, output, scan_after_pull, skip_safety_check):
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
        
        if scan_after_pull:
            logger.info("Starting automatic scan...")
            
            # Find model files to scan
            parser_manager = ParserManager(ctx.obj.config.dict())
            model_files = []
            
            for file in model_dir.rglob('*'):
                if file.is_file() and parser_manager.is_supported(file):
                    model_files.append(file)
            
            if model_files:
                logger.info(f"Found {len(model_files)} model files to scan")
                
                for model_file in model_files:
                    logger.info(f"\nScanning: {model_file.name}")
                    ctx.invoke(scan, model_path=str(model_file))
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
@click.option('--project-id', help='Google Cloud project ID')
@click.option('--credentials', type=click.Path(exists=True), 
              help='Path to GCP credentials JSON')
@click.option('--hf-token', help='HuggingFace API token')
@click.option('--ollama-url', help='Ollama API URL')
@click.pass_context
def configure(ctx, project_id, credentials, hf_token, ollama_url):
    """Configure LLMShield settings."""
    updated = False
    
    if project_id:
        ctx.obj.set('vertex_ai.project_id', project_id)
        logger.success(f"Set Vertex AI project ID: {project_id}")
        updated = True
    
    if credentials:
        ctx.obj.set('vertex_ai.credentials_path', credentials)
        logger.success(f"Set Vertex AI credentials: {credentials}")
        updated = True
    
    if hf_token:
        ctx.obj.set('huggingface.api_token', hf_token)
        logger.success("Set HuggingFace API token")
        updated = True
    
    if ollama_url:
        ctx.obj.set('ollama.api_url', ollama_url)
        logger.success(f"Set Ollama API URL: {ollama_url}")
        updated = True
    
    if updated:
        ctx.obj.save_config()
        logger.success("Configuration saved successfully!")
    else:
        logger.warning("No configuration changes made")


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
        ("PyTorch", ".pt, .pth", "✅"),
        ("TensorFlow", ".pb, .h5", "✅"),
        ("ONNX", ".onnx", "✅"),
        ("Pickle", ".pkl", "✅"),
        ("Safetensors", ".safetensors", "✅"),
        ("Keras", ".keras", "🚧"),
        ("JAX", ".jax", "🚧"),
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