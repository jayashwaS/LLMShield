"""Command-line interface for LLMShield - Updated with directory scanning."""

import click
from pathlib import Path
from rich.console import Console

from llmshield.core.config import ConfigManager
from llmshield.core.logger import get_logger, setup_logger
from llmshield.utils.banner import BANNER

logger = get_logger(__name__)
console = Console()


@click.group()
@click.option('--config', '-c', type=click.Path(exists=True), help='Configuration file path')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--debug', is_flag=True, help='Enable debug output')
@click.option('--log-file', type=click.Path(), help='Log file path')
@click.pass_context
def cli(ctx, config, verbose, debug, log_file):
    """LLMShield - AI Model Security Scanner"""
    # Ensure context object
    ctx.ensure_object(dict)
    
    # Set log level
    log_level = 'INFO'
    if debug:
        log_level = 'DEBUG'
    elif verbose:
        log_level = 'INFO'
    
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
              type=click.Choice(['json', 'html', 'text']), 
              default=['json', 'html'], help='Report formats')
@click.option('--recursive', '-r', is_flag=True, help='Recursively scan subdirectories')
@click.option('--extensions', '-e', multiple=True, help='File extensions to scan')
@click.option('--scanners', '-s', multiple=True, help='Specific scanners to use')
@click.option('--no-report', is_flag=True, help='Skip report generation')
@click.option('--summary-only', is_flag=True, help='Show summary only, no detailed output')
@click.pass_context
def scan(ctx, path, output, format, recursive, extensions, scanners, no_report, summary_only):
    """Scan model files or directories for vulnerabilities."""
    try:
        from llmshield.cli.scan_directory import scan_directory
        
        # Default extensions if not provided
        if not extensions:
            extensions = ['.pt', '.pth', '.pkl', '.pb', '.h5', '.onnx', '.safetensors', '.bin']
        else:
            extensions = list(extensions)
        
        # Default output directory
        if not output:
            output = ctx.obj.get('report.output_dir', 'reports')
        
        # Perform scan
        files_scanned, total_vulns, max_severity = scan_directory(
            path=path,
            output=output if not no_report else None,
            formats=list(format),
            recursive=recursive,
            extensions=extensions,
            scanners=list(scanners) if scanners else None,
            config=ctx.obj.config.dict()
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
        
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise click.ClickException(str(e))


@cli.command()
@click.option('--source', '-s', type=click.Choice(['huggingface', 'ollama']), 
              required=True, help='Model source')
@click.argument('model_id')
@click.option('--output', '-o', type=click.Path(), help='Output directory')
@click.option('--scan-after-pull', is_flag=True, help='Automatically scan after pulling')
@click.pass_context
def pull(ctx, source, model_id, output, scan_after_pull):
    """Pull models from HuggingFace or Ollama."""
    try:
        if source == 'huggingface':
            from llmshield.integrations.huggingface import HuggingFaceIntegration
            integration = HuggingFaceIntegration(ctx.obj.config.dict())
            model_path = integration.pull_model(model_id, output_dir=output)
            
            if scan_after_pull and model_path:
                logger.info("Starting automatic scan of pulled model...")
                ctx.invoke(scan, path=str(model_path), recursive=False)
                
        elif source == 'ollama':
            from llmshield.integrations.ollama import OllamaIntegration
            integration = OllamaIntegration(ctx.obj.config.dict())
            model_path = integration.pull_model(model_id, output_dir=output)
            
            if scan_after_pull and model_path:
                logger.info("Starting automatic scan of pulled model...")
                ctx.invoke(scan, path=str(model_path), recursive=False)
                
    except Exception as e:
        logger.error(f"Pull failed: {e}")
        raise click.ClickException(str(e))


@cli.command('list-scanners')
@click.pass_context
def list_scanners(ctx):
    """List all available vulnerability scanners."""
    try:
        from llmshield.scanners import ScannerManager
        from rich.table import Table
        
        manager = ScannerManager()
        manager.initialize_default_scanners(ctx.obj.config.dict())
        
        # Create table
        table = Table(title="Available Scanners", show_header=True)
        table.add_column("Scanner", style="cyan", width=25)
        table.add_column("Description", style="yellow")
        table.add_column("Formats", style="green")
        
        for scanner_info in manager.list_scanners():
            table.add_row(
                scanner_info['name'],
                scanner_info['description'],
                scanner_info['formats']
            )
        
        console.print(table)
        
    except Exception as e:
        logger.error(f"Failed to list scanners: {e}")
        raise click.ClickException(str(e))


@cli.command('list-parsers')
@click.pass_context
def list_parsers(ctx):
    """List all available model parsers."""
    try:
        from llmshield.parsers import ParserManager
        from rich.table import Table
        
        manager = ParserManager(ctx.obj.config.dict())
        
        # Create table
        table = Table(title="Supported Model Formats", show_header=True)
        table.add_column("Framework", style="cyan", width=20)
        table.add_column("Extensions", style="yellow")
        
        for framework, extensions in manager.get_supported_formats().items():
            table.add_row(framework, ", ".join(extensions))
        
        console.print(table)
        
    except Exception as e:
        logger.error(f"Failed to list parsers: {e}")
        raise click.ClickException(str(e))


@cli.command()
@click.pass_context
def configure(ctx):
    """Interactive configuration setup."""
    try:
        from llmshield.utils.setup import interactive_setup
        interactive_setup(ctx.obj)
        logger.info("Configuration completed successfully!")
        
    except Exception as e:
        logger.error(f"Configuration failed: {e}")
        raise click.ClickException(str(e))


@cli.command()
@click.option('--key', '-k', help='Configuration key (e.g., scanner.timeout)')
@click.option('--value', '-v', help='Configuration value')
@click.option('--show', is_flag=True, help='Show current configuration')
@click.pass_context
def config(ctx, key, value, show):
    """Get or set configuration values."""
    try:
        if show:
            # Show all configuration
            import yaml
            console.print(yaml.dump(ctx.obj.config.dict(), default_flow_style=False))
        elif key and value:
            # Set configuration value
            ctx.obj.set(key, value)
            ctx.obj.save()
            logger.info(f"Set {key} = {value}")
        elif key:
            # Get configuration value
            value = ctx.obj.get(key)
            console.print(f"{key} = {value}")
        else:
            # Show usage
            console.print("Usage: llmshield config --key <key> --value <value>")
            console.print("       llmshield config --key <key>")
            console.print("       llmshield config --show")
            
    except Exception as e:
        logger.error(f"Configuration operation failed: {e}")
        raise click.ClickException(str(e))


if __name__ == '__main__':
    cli()