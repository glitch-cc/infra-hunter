#!/usr/bin/env python3
"""
Signature Management CLI for infra-hunter.

Usage:
    python sig_cli.py list [--category=<cat>] [--enabled]
    python sig_cli.py show <sig_id>
    python sig_cli.py create
    python sig_cli.py edit <sig_id>
    python sig_cli.py test <sig_id> [--limit=<n>]
    python sig_cli.py enable <sig_id>
    python sig_cli.py disable <sig_id>
    python sig_cli.py delete <sig_id>
    python sig_cli.py search <query>
    python sig_cli.py stats
    python sig_cli.py export <sig_id> [--format=json|yaml]
    python sig_cli.py import <file>
"""
import os
import sys
import json
import yaml
import click
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich import box

sys.path.insert(0, str(Path(__file__).parent))

from signatures.manager import (
    SignatureManager, Signature, Condition,
    CATEGORIES, CONFIDENCE_LEVELS, SEVERITY_LEVELS, CONDITION_TYPES, OPERATORS
)

console = Console()


@click.group()
def cli():
    """Infra-Hunter Signature Management"""
    pass


@cli.command("list")
@click.option("--category", "-c", help="Filter by category")
@click.option("--enabled/--all", default=False, help="Show only enabled signatures")
@click.option("--confidence", help="Filter by confidence level")
def list_sigs(category, enabled, confidence):
    """List all signatures."""
    mgr = SignatureManager()
    sigs = mgr.list(category=category, enabled_only=enabled)
    
    if confidence:
        sigs = [s for s in sigs if s.confidence == confidence]
    
    if not sigs:
        console.print("[yellow]No signatures found.[/yellow]")
        return
    
    table = Table(title="Signatures", box=box.ROUNDED)
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("Category", style="magenta")
    table.add_column("Confidence", style="green")
    table.add_column("Status", style="yellow")
    table.add_column("Conditions", justify="right")
    
    for sig in sigs:
        status = "✓ enabled" if sig.enabled else "○ disabled"
        conf_color = {"high": "green", "medium": "yellow", "low": "red"}.get(sig.confidence, "white")
        table.add_row(
            sig.id,
            sig.name[:40] + ("..." if len(sig.name) > 40 else ""),
            sig.category,
            f"[{conf_color}]{sig.confidence}[/{conf_color}]",
            status,
            str(len(sig.conditions)),
        )
    
    console.print(table)
    console.print(f"\nTotal: {len(sigs)} signatures")


@cli.command("show")
@click.argument("sig_id")
@click.option("--format", "-f", "fmt", type=click.Choice(["pretty", "yaml", "json"]), default="pretty")
def show_sig(sig_id, fmt):
    """Show signature details."""
    mgr = SignatureManager()
    sig = mgr.get(sig_id)
    
    if not sig:
        console.print(f"[red]Signature not found: {sig_id}[/red]")
        return
    
    if fmt == "yaml":
        console.print(Syntax(yaml.dump(sig.to_dict(), default_flow_style=False), "yaml"))
        return
    elif fmt == "json":
        console.print(Syntax(json.dumps(sig.to_dict(), indent=2), "json"))
        return
    
    # Pretty format
    conf_color = {"high": "green", "medium": "yellow", "low": "red"}.get(sig.confidence, "white")
    sev_color = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "blue"}.get(sig.severity, "white")
    
    console.print(Panel(f"[bold cyan]{sig.name}[/bold cyan]", subtitle=f"v{sig.version}"))
    console.print(f"[dim]ID:[/dim] {sig.id}")
    console.print(f"[dim]Category:[/dim] {sig.category}")
    console.print(f"[dim]Status:[/dim] {'✓ Enabled' if sig.enabled else '○ Disabled'}")
    console.print(f"[dim]Confidence:[/dim] [{conf_color}]{sig.confidence}[/{conf_color}]")
    console.print(f"[dim]Severity:[/dim] [{sev_color}]{sig.severity}[/{sev_color}]")
    if sig.author:
        console.print(f"[dim]Author:[/dim] {sig.author}")
    
    console.print(f"\n[bold]Description:[/bold]\n{sig.description}")
    
    if sig.attribution_actors:
        console.print(f"\n[bold]Attribution:[/bold]")
        console.print(f"  Actors: {', '.join(sig.attribution_actors)}")
        console.print(f"  Confidence: {sig.attribution_confidence}")
        if sig.attribution_note:
            console.print(f"  Note: {sig.attribution_note}")
    
    console.print(f"\n[bold]Detection Logic[/bold] (match: {sig.logic_match})")
    for i, cond in enumerate(sig.conditions, 1):
        console.print(f"  {i}. [cyan]{cond.name}[/cyan]")
        console.print(f"     Type: {cond.type}")
        console.print(f"     Field: {cond.field}")
        console.print(f"     {cond.operator}: {cond.value}")
        console.print(f"     Weight: {cond.weight}")
        if cond.note:
            console.print(f"     Note: [dim]{cond.note}[/dim]")
    
    if sig.queries_censys:
        console.print(f"\n[bold]Censys Query:[/bold]")
        console.print(f"  {sig.queries_censys}")
    
    if sig.queries_shodan:
        console.print(f"\n[bold]Shodan Query:[/bold]")
        console.print(f"  {sig.queries_shodan}")
    
    if sig.references:
        console.print(f"\n[bold]References:[/bold]")
        for ref in sig.references:
            title = ref.get("title", ref.get("url", ""))
            url = ref.get("url", "")
            console.print(f"  • {title}: {url}")
    
    if sig.changelog:
        console.print(f"\n[bold]Changelog:[/bold]")
        for entry in sig.changelog[:3]:
            console.print(f"  v{entry.get('version', '?')} ({entry.get('date', '?')}): {entry.get('changes', '')}")


@cli.command("create")
@click.option("--interactive/--no-interactive", "-i", default=True)
def create_sig(interactive):
    """Create a new signature."""
    if not interactive:
        console.print("[yellow]Non-interactive mode not yet supported. Use --interactive.[/yellow]")
        return
    
    console.print(Panel("[bold]Create New Signature[/bold]"))
    
    # Basic info
    sig_id = click.prompt("Signature ID (lowercase-with-hyphens)")
    name = click.prompt("Name")
    
    console.print(f"[dim]Categories: {', '.join(CATEGORIES)}[/dim]")
    category = click.prompt("Category", type=click.Choice(CATEGORIES))
    
    description = click.prompt("Description")
    author = click.prompt("Author", default="")
    
    # Detection logic
    console.print(f"\n[bold]Detection Logic[/bold]")
    logic_match = click.prompt("Match type", type=click.Choice(["any", "all"]), default="any")
    
    conditions = []
    console.print("\n[dim]Add conditions (empty name to finish)[/dim]")
    
    while True:
        cond_name = click.prompt("\nCondition name", default="")
        if not cond_name:
            break
        
        console.print(f"[dim]Types: {', '.join(CONDITION_TYPES)}[/dim]")
        cond_type = click.prompt("Type", type=click.Choice(CONDITION_TYPES))
        
        cond_field = click.prompt("Field (e.g., services.tls.certificates.leaf_data.fingerprint)")
        cond_value = click.prompt("Value")
        cond_weight = click.prompt("Weight", type=int, default=50)
        cond_note = click.prompt("Note (optional)", default="")
        
        conditions.append(Condition(
            name=cond_name,
            type=cond_type,
            field=cond_field,
            operator="equals",
            value=cond_value,
            weight=cond_weight,
            note=cond_note or None,
        ))
        console.print(f"[green]Added condition: {cond_name}[/green]")
    
    if not conditions:
        console.print("[red]At least one condition is required.[/red]")
        return
    
    # Metadata
    console.print(f"\n[bold]Metadata[/bold]")
    console.print(f"[dim]Confidence: {', '.join(CONFIDENCE_LEVELS)}[/dim]")
    confidence = click.prompt("Confidence", type=click.Choice(CONFIDENCE_LEVELS), default="medium")
    
    console.print(f"[dim]Severity: {', '.join(SEVERITY_LEVELS)}[/dim]")
    severity = click.prompt("Severity", type=click.Choice(SEVERITY_LEVELS), default="medium")
    
    # Attribution (optional)
    actors_str = click.prompt("Attribution actors (comma-separated, optional)", default="")
    actors = [a.strip() for a in actors_str.split(",") if a.strip()] if actors_str else []
    
    # Build signature
    from datetime import date
    sig = Signature(
        id=sig_id,
        name=name,
        version="1.0.0",
        category=category,
        description=description,
        logic_match=logic_match,
        conditions=conditions,
        author=author or None,
        attribution_actors=actors,
        confidence=confidence,
        severity=severity,
        last_verified=date.today().isoformat(),
    )
    sig.queries_censys = sig.generate_censys_query()
    
    # Validate
    errors = sig.validate()
    if errors:
        console.print("[red]Validation errors:[/red]")
        for e in errors:
            console.print(f"  • {e}")
        return
    
    # Save
    mgr = SignatureManager()
    path = mgr.save(sig)
    console.print(f"\n[green]✓ Saved to: {path}[/green]")


@cli.command("edit")
@click.argument("sig_id")
def edit_sig(sig_id):
    """Edit a signature (opens in $EDITOR)."""
    mgr = SignatureManager()
    mgr.load_all()
    sig = mgr.get(sig_id)
    
    if not sig or not sig.file_path:
        console.print(f"[red]Signature not found: {sig_id}[/red]")
        return
    
    editor = os.environ.get("EDITOR", "nano")
    os.system(f"{editor} {sig.file_path}")
    
    # Reload and validate
    try:
        reloaded = mgr.load_file(sig.file_path)
        errors = reloaded.validate()
        if errors:
            console.print("[yellow]Validation warnings:[/yellow]")
            for e in errors:
                console.print(f"  • {e}")
        else:
            console.print("[green]✓ Signature valid[/green]")
    except Exception as e:
        console.print(f"[red]Error reloading: {e}[/red]")


@cli.command("enable")
@click.argument("sig_id")
def enable_sig(sig_id):
    """Enable a signature."""
    mgr = SignatureManager()
    sig = mgr.get(sig_id)
    
    if not sig:
        console.print(f"[red]Signature not found: {sig_id}[/red]")
        return
    
    sig.enabled = True
    mgr.save(sig)
    console.print(f"[green]✓ Enabled: {sig_id}[/green]")


@cli.command("disable")
@click.argument("sig_id")
def disable_sig(sig_id):
    """Disable a signature."""
    mgr = SignatureManager()
    sig = mgr.get(sig_id)
    
    if not sig:
        console.print(f"[red]Signature not found: {sig_id}[/red]")
        return
    
    sig.enabled = False
    mgr.save(sig)
    console.print(f"[yellow]○ Disabled: {sig_id}[/yellow]")


@cli.command("delete")
@click.argument("sig_id")
@click.confirmation_option(prompt="Are you sure you want to delete this signature?")
def delete_sig(sig_id):
    """Delete a signature."""
    mgr = SignatureManager()
    
    if mgr.delete(sig_id):
        console.print(f"[red]✗ Deleted: {sig_id}[/red]")
    else:
        console.print(f"[red]Signature not found: {sig_id}[/red]")


@cli.command("search")
@click.argument("query")
def search_sigs(query):
    """Search signatures by name, ID, or description."""
    mgr = SignatureManager()
    results = mgr.search(query)
    
    if not results:
        console.print(f"[yellow]No signatures matching '{query}'[/yellow]")
        return
    
    table = Table(title=f"Search: '{query}'", box=box.ROUNDED)
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("Category", style="magenta")
    
    for sig in results:
        table.add_row(sig.id, sig.name, sig.category)
    
    console.print(table)


@cli.command("stats")
def stats_cmd():
    """Show signature statistics."""
    mgr = SignatureManager()
    stats = mgr.stats()
    
    console.print(Panel("[bold]Signature Statistics[/bold]"))
    console.print(f"Total signatures: [cyan]{stats['total']}[/cyan]")
    console.print(f"Enabled: [green]{stats['enabled']}[/green]")
    console.print(f"Disabled: [dim]{stats['disabled']}[/dim]")
    
    console.print("\n[bold]By Category:[/bold]")
    for cat, count in sorted(stats['by_category'].items()):
        console.print(f"  {cat}: {count}")
    
    console.print("\n[bold]By Confidence:[/bold]")
    for conf in ["high", "medium", "low"]:
        count = stats['by_confidence'].get(conf, 0)
        color = {"high": "green", "medium": "yellow", "low": "red"}.get(conf, "white")
        console.print(f"  [{color}]{conf}[/{color}]: {count}")


@cli.command("test")
@click.argument("sig_id")
@click.option("--limit", "-n", default=10, help="Max results")
@click.option("--source", "-s", type=click.Choice(["censys", "shodan"]), default="censys")
def test_sig(sig_id, limit, source):
    """Test a signature against live data."""
    mgr = SignatureManager()
    sig = mgr.get(sig_id)
    
    if not sig:
        console.print(f"[red]Signature not found: {sig_id}[/red]")
        return
    
    query = sig.queries_censys if source == "censys" else sig.queries_shodan
    if not query:
        query = sig.generate_censys_query()
    
    if not query:
        console.print("[red]No query available for this signature.[/red]")
        return
    
    console.print(f"[bold]Testing: {sig.name}[/bold]")
    console.print(f"Query: {query}")
    console.print(f"Source: {source}")
    console.print()
    
    if source == "censys":
        try:
            from scanner import CensysScanner
            scanner = CensysScanner()
            results = scanner.search(query, limit=limit)
            
            if not results:
                console.print("[yellow]No results found.[/yellow]")
                return
            
            table = Table(title=f"Results ({len(results)} hosts)", box=box.ROUNDED)
            table.add_column("IP", style="cyan")
            table.add_column("ASN", style="magenta")
            table.add_column("Country", style="green")
            table.add_column("Services")
            
            for host in results:
                ip = host.get("ip", "?")
                asn = str(host.get("autonomous_system", {}).get("asn", "?"))
                country = host.get("location", {}).get("country_code", "?")
                services = ", ".join([
                    f"{s.get('port', '?')}/{s.get('transport_protocol', '?')}"
                    for s in host.get("services", [])[:3]
                ])
                table.add_row(ip, asn, country, services)
            
            console.print(table)
            
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
    else:
        console.print("[yellow]Shodan testing not yet implemented.[/yellow]")


@cli.command("export")
@click.argument("sig_id")
@click.option("--format", "-f", "fmt", type=click.Choice(["yaml", "json"]), default="yaml")
@click.option("--output", "-o", help="Output file")
def export_sig(sig_id, fmt, output):
    """Export a signature."""
    mgr = SignatureManager()
    sig = mgr.get(sig_id)
    
    if not sig:
        console.print(f"[red]Signature not found: {sig_id}[/red]")
        return
    
    data = sig.to_dict()
    
    if fmt == "yaml":
        content = yaml.dump(data, default_flow_style=False, sort_keys=False)
    else:
        content = json.dumps(data, indent=2)
    
    if output:
        with open(output, "w") as f:
            f.write(content)
        console.print(f"[green]Exported to: {output}[/green]")
    else:
        console.print(content)


@cli.command("import")
@click.argument("file_path", type=click.Path(exists=True))
def import_sig(file_path):
    """Import a signature from YAML/JSON file."""
    path = Path(file_path)
    
    with open(path) as f:
        if path.suffix in [".yaml", ".yml"]:
            data = yaml.safe_load(f)
        else:
            data = json.load(f)
    
    sig = Signature.from_dict(data)
    errors = sig.validate()
    
    if errors:
        console.print("[red]Validation errors:[/red]")
        for e in errors:
            console.print(f"  • {e}")
        if not click.confirm("Import anyway?"):
            return
    
    mgr = SignatureManager()
    saved_path = mgr.save(sig)
    console.print(f"[green]✓ Imported: {sig.id} -> {saved_path}[/green]")


if __name__ == "__main__":
    cli()
