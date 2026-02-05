#!/usr/bin/env python3
"""
Infrastructure Hunter CLI.
Track threat actor infrastructure patterns.
"""
import os
import sys
import json
import click
from datetime import datetime, timedelta
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

# Add parent to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models import (
    get_engine, get_session, init_db,
    Actor, Pattern, Host, Match, ScanJob
)
from scanner import (
    CensysScanner, PatternMatcher, build_censys_query,
    KNOWN_PATTERNS, ScanResult
)

console = Console()


@click.group()
@click.option('--db', envvar='INFRA_HUNTER_DB', default='postgresql://localhost/infra_hunter',
              help='Database connection string')
@click.pass_context
def cli(ctx, db):
    """Infrastructure Pattern Intelligence - Hunt threat actor infrastructure."""
    ctx.ensure_object(dict)
    ctx.obj['db_url'] = db


# =====================
# Database Commands
# =====================

@cli.command('init')
@click.option('--seed', is_flag=True, help='Seed with known threat actor patterns')
@click.pass_context
def init_database(ctx, seed):
    """Initialize the database and optionally seed patterns."""
    console.print("[bold blue]Initializing database...[/bold blue]")
    
    try:
        engine = get_engine(ctx.obj['db_url'])
        init_db(engine)
        console.print("[green]✓[/green] Database tables created")
        
        if seed:
            session = get_session(engine)
            seed_patterns(session)
            session.close()
            console.print("[green]✓[/green] Seeded with known threat actor patterns")
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


def seed_patterns(session):
    """Seed the database with known patterns."""
    actors_cache = {}
    
    for key, data in KNOWN_PATTERNS.items():
        # Check if pattern exists
        existing = session.query(Pattern).filter_by(name=data['name']).first()
        if existing:
            continue
        
        # Create actor if needed
        actor_id = None
        actor_name = data.get('actor')
        if actor_name:
            if actor_name not in actors_cache:
                actor = session.query(Actor).filter_by(name=actor_name).first()
                if not actor:
                    actor = Actor(name=actor_name)
                    session.add(actor)
                    session.flush()
                actors_cache[actor_name] = actor.id
            actor_id = actors_cache[actor_name]
        
        # Build Censys query
        censys_query = build_censys_query(data['pattern_type'], data['definition'])
        
        # Create pattern
        pattern = Pattern(
            name=data['name'],
            pattern_type=data['pattern_type'],
            definition=data['definition'],
            censys_query=censys_query,
            actor_id=actor_id,
            description=data.get('description'),
            confidence=data.get('confidence', 'medium'),
            source='seed',
            references=data.get('references', []),
        )
        session.add(pattern)
    
    session.commit()


# =====================
# Pattern Commands
# =====================

@cli.group('pattern')
def pattern_group():
    """Manage infrastructure patterns."""
    pass


@pattern_group.command('list')
@click.option('--actor', help='Filter by actor name')
@click.option('--type', 'pattern_type', help='Filter by pattern type')
@click.pass_context
def list_patterns(ctx, actor, pattern_type):
    """List all patterns."""
    session = get_session(get_engine(ctx.obj['db_url']))
    
    query = session.query(Pattern)
    
    if actor:
        query = query.join(Actor).filter(Actor.name.ilike(f'%{actor}%'))
    if pattern_type:
        query = query.filter(Pattern.pattern_type == pattern_type)
    
    patterns = query.all()
    
    table = Table(title="Infrastructure Patterns")
    table.add_column("ID", style="dim")
    table.add_column("Name", style="cyan")
    table.add_column("Type", style="green")
    table.add_column("Actor", style="yellow")
    table.add_column("Confidence")
    table.add_column("Matches", justify="right")
    table.add_column("Enabled")
    
    for p in patterns:
        table.add_row(
            str(p.id),
            p.name,
            p.pattern_type,
            p.actor.name if p.actor else "-",
            p.confidence,
            str(p.total_matches),
            "✓" if p.enabled else "✗"
        )
    
    console.print(table)
    session.close()


@pattern_group.command('show')
@click.argument('name_or_id')
@click.pass_context
def show_pattern(ctx, name_or_id):
    """Show pattern details."""
    session = get_session(get_engine(ctx.obj['db_url']))
    
    # Try ID first, then name
    if name_or_id.isdigit():
        pattern = session.query(Pattern).get(int(name_or_id))
    else:
        pattern = session.query(Pattern).filter_by(name=name_or_id).first()
    
    if not pattern:
        console.print(f"[red]Pattern not found: {name_or_id}[/red]")
        sys.exit(1)
    
    console.print(Panel(f"[bold cyan]{pattern.name}[/bold cyan]", subtitle=f"ID: {pattern.id}"))
    console.print(f"[bold]Type:[/bold] {pattern.pattern_type}")
    console.print(f"[bold]Actor:[/bold] {pattern.actor.name if pattern.actor else 'Unattributed'}")
    console.print(f"[bold]Confidence:[/bold] {pattern.confidence}")
    console.print(f"[bold]Enabled:[/bold] {pattern.enabled}")
    console.print(f"[bold]Total Matches:[/bold] {pattern.total_matches}")
    console.print(f"[bold]Last Match:[/bold] {pattern.last_match_at or 'Never'}")
    console.print()
    console.print("[bold]Definition:[/bold]")
    console.print(json.dumps(pattern.definition, indent=2))
    console.print()
    console.print("[bold]Censys Query:[/bold]")
    console.print(f"[dim]{pattern.censys_query}[/dim]")
    
    if pattern.description:
        console.print()
        console.print(f"[bold]Description:[/bold] {pattern.description}")
    
    if pattern.references:
        console.print()
        console.print("[bold]References:[/bold]")
        for ref in pattern.references:
            console.print(f"  • {ref}")
    
    session.close()


@pattern_group.command('add')
@click.option('--name', required=True, help='Pattern name')
@click.option('--type', 'pattern_type', required=True, 
              type=click.Choice(['cert_subject_dn', 'cert_issuer_dn', 'cert_fingerprint',
                                'jarm', 'http_headers', 'http_body_hash', 'asn',
                                'hosting_provider', 'port_combo', 'domain_regex', 'composite']),
              help='Pattern type')
@click.option('--definition', required=True, help='Pattern definition (JSON)')
@click.option('--actor', help='Attribute to actor')
@click.option('--confidence', default='medium', type=click.Choice(['high', 'medium', 'low']))
@click.option('--description', help='Pattern description')
@click.pass_context
def add_pattern(ctx, name, pattern_type, definition, actor, confidence, description):
    """Add a new pattern."""
    session = get_session(get_engine(ctx.obj['db_url']))
    
    try:
        def_dict = json.loads(definition)
    except json.JSONDecodeError as e:
        console.print(f"[red]Invalid JSON in definition: {e}[/red]")
        sys.exit(1)
    
    # Find actor if specified
    actor_id = None
    if actor:
        actor_obj = session.query(Actor).filter_by(name=actor).first()
        if not actor_obj:
            actor_obj = Actor(name=actor)
            session.add(actor_obj)
            session.flush()
        actor_id = actor_obj.id
    
    # Build Censys query
    censys_query = build_censys_query(pattern_type, def_dict)
    
    pattern = Pattern(
        name=name,
        pattern_type=pattern_type,
        definition=def_dict,
        censys_query=censys_query,
        actor_id=actor_id,
        confidence=confidence,
        description=description,
    )
    session.add(pattern)
    session.commit()
    
    console.print(f"[green]✓[/green] Added pattern: {name} (ID: {pattern.id})")
    console.print(f"[dim]Censys query: {censys_query}[/dim]")
    
    session.close()


# =====================
# Scan Commands
# =====================

@cli.command('scan')
@click.option('--pattern', 'pattern_name', help='Scan for specific pattern')
@click.option('--all', 'scan_all', is_flag=True, help='Scan all enabled patterns')
@click.option('--query', help='Run custom Censys query')
@click.option('--max-results', default=100, help='Maximum results per pattern')
@click.pass_context
def scan(ctx, pattern_name, scan_all, query, max_results):
    """Scan for hosts matching patterns."""
    session = get_session(get_engine(ctx.obj['db_url']))
    
    try:
        scanner = CensysScanner()
        matcher = PatternMatcher()
    except Exception as e:
        console.print(f"[red]Scanner error: {e}[/red]")
        sys.exit(1)
    
    patterns_to_scan = []
    
    if query:
        # Ad-hoc query
        console.print(f"[bold]Running custom query:[/bold] {query}")
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Scanning...", total=None)
            results = scanner.search(query, max_results=max_results)
            progress.remove_task(task)
        
        console.print(f"[green]Found {len(results)} hosts[/green]")
        
        table = Table(title="Scan Results")
        table.add_column("IP", style="cyan")
        table.add_column("Country")
        table.add_column("ASN")
        table.add_column("JARM", style="dim")
        table.add_column("Cert Subject", max_width=40)
        
        for r in results[:20]:  # Show first 20
            table.add_row(
                r.ip,
                r.country or "-",
                f"{r.asn} ({r.asn_name[:20]}...)" if r.asn_name else str(r.asn) if r.asn else "-",
                r.jarm[:20] + "..." if r.jarm else "-",
                (r.cert_subject[:37] + "...") if r.cert_subject and len(r.cert_subject) > 40 else r.cert_subject or "-"
            )
        
        console.print(table)
        if len(results) > 20:
            console.print(f"[dim]... and {len(results) - 20} more[/dim]")
        
    elif pattern_name:
        pattern = session.query(Pattern).filter_by(name=pattern_name).first()
        if not pattern:
            console.print(f"[red]Pattern not found: {pattern_name}[/red]")
            sys.exit(1)
        patterns_to_scan = [pattern]
        
    elif scan_all:
        patterns_to_scan = session.query(Pattern).filter_by(enabled=True).all()
        if not patterns_to_scan:
            console.print("[yellow]No enabled patterns found[/yellow]")
            sys.exit(0)
    else:
        console.print("[yellow]Specify --pattern, --all, or --query[/yellow]")
        sys.exit(1)
    
    # Scan patterns
    total_new = 0
    for pattern in patterns_to_scan:
        console.print(f"\n[bold blue]Scanning pattern:[/bold blue] {pattern.name}")
        console.print(f"[dim]Query: {pattern.censys_query}[/dim]")
        
        if not pattern.censys_query:
            console.print("[yellow]  No Censys query defined, skipping[/yellow]")
            continue
        
        # Create scan job
        job = ScanJob(
            pattern_id=pattern.id,
            job_type='pattern_scan',
            status='running',
            query=pattern.censys_query,
            started_at=datetime.utcnow()
        )
        session.add(job)
        session.commit()
        
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Scanning Censys...", total=None)
                results = scanner.search(pattern.censys_query, max_results=max_results)
                progress.remove_task(task)
            
            console.print(f"  Found {len(results)} hosts")
            
            # Process results
            new_matches = 0
            for result in results:
                # Check if host exists
                host = session.query(Host).filter_by(ip=result.ip).first()
                if not host:
                    host = Host(
                        ip=result.ip,
                        asn=result.asn,
                        asn_name=result.asn_name,
                        country=result.country,
                        city=result.city,
                        cert_subject=result.cert_subject,
                        cert_issuer=result.cert_issuer,
                        cert_fingerprint=result.cert_fingerprint,
                        cert_not_before=result.cert_not_before,
                        cert_not_after=result.cert_not_after,
                        cert_self_signed=result.cert_self_signed,
                        jarm=result.jarm,
                        http_status=result.http_status,
                        http_headers=result.http_headers,
                        http_body_hash=result.http_body_hash,
                        http_server=result.http_server,
                        ports=result.ports,
                        services=result.services,
                        hostnames=result.hostnames,
                        censys_data=result.raw_data,
                    )
                    session.add(host)
                    session.flush()
                else:
                    # Update host
                    host.last_seen = datetime.utcnow()
                    host.scan_count += 1
                
                # Verify pattern match
                matched, details = matcher.matches(result, pattern.pattern_type, pattern.definition)
                
                if matched:
                    # Check if match exists
                    existing_match = session.query(Match).filter_by(
                        pattern_id=pattern.id, host_id=host.id
                    ).first()
                    
                    if not existing_match:
                        match = Match(
                            pattern_id=pattern.id,
                            host_id=host.id,
                            match_details=details,
                        )
                        session.add(match)
                        new_matches += 1
            
            # Update pattern stats
            pattern.total_matches += new_matches
            if new_matches > 0:
                pattern.last_match_at = datetime.utcnow()
            
            # Update job
            job.status = 'completed'
            job.completed_at = datetime.utcnow()
            job.hosts_found = len(results)
            job.new_matches = new_matches
            
            session.commit()
            
            console.print(f"  [green]New matches: {new_matches}[/green]")
            total_new += new_matches
            
        except Exception as e:
            job.status = 'failed'
            job.error_message = str(e)
            session.commit()
            console.print(f"  [red]Error: {e}[/red]")
    
    console.print(f"\n[bold green]Total new matches: {total_new}[/bold green]")
    session.close()


# =====================
# Match Commands
# =====================

@cli.command('matches')
@click.option('--hours', default=72, help='Show matches from last N hours')
@click.option('--pattern', 'pattern_name', help='Filter by pattern name')
@click.option('--actor', help='Filter by actor name')
@click.option('--status', type=click.Choice(['new', 'reviewed', 'confirmed', 'false_positive']))
@click.pass_context
def list_matches(ctx, hours, pattern_name, actor, status):
    """List pattern matches."""
    session = get_session(get_engine(ctx.obj['db_url']))
    
    since = datetime.utcnow() - timedelta(hours=hours)
    
    query = session.query(Match).filter(Match.matched_at >= since)
    
    if pattern_name:
        query = query.join(Pattern).filter(Pattern.name.ilike(f'%{pattern_name}%'))
    
    if actor:
        query = query.join(Pattern).join(Actor).filter(Actor.name.ilike(f'%{actor}%'))
    
    if status:
        query = query.filter(Match.status == status)
    
    matches = query.order_by(Match.matched_at.desc()).all()
    
    if not matches:
        console.print(f"[yellow]No matches found in the last {hours} hours[/yellow]")
        return
    
    table = Table(title=f"Matches (last {hours}h)")
    table.add_column("ID", style="dim")
    table.add_column("IP", style="cyan")
    table.add_column("Pattern", style="green")
    table.add_column("Actor", style="yellow")
    table.add_column("Country")
    table.add_column("Status")
    table.add_column("Matched At")
    
    for m in matches:
        table.add_row(
            str(m.id),
            m.host.ip,
            m.pattern.name,
            m.pattern.actor.name if m.pattern.actor else "-",
            m.host.country or "-",
            m.status,
            m.matched_at.strftime('%Y-%m-%d %H:%M')
        )
    
    console.print(table)
    console.print(f"\n[bold]Total: {len(matches)} matches[/bold]")
    session.close()


@cli.command('host')
@click.argument('ip')
@click.pass_context
def show_host(ctx, ip):
    """Show details for a specific host."""
    session = get_session(get_engine(ctx.obj['db_url']))
    
    host = session.query(Host).filter_by(ip=ip).first()
    
    if not host:
        console.print(f"[yellow]Host not in database: {ip}[/yellow]")
        console.print("[dim]Try scanning first or fetching from Censys[/dim]")
        return
    
    console.print(Panel(f"[bold cyan]{host.ip}[/bold cyan]"))
    console.print(f"[bold]Country:[/bold] {host.country or 'Unknown'}")
    console.print(f"[bold]City:[/bold] {host.city or 'Unknown'}")
    console.print(f"[bold]ASN:[/bold] {host.asn} ({host.asn_name})" if host.asn else "[bold]ASN:[/bold] Unknown")
    console.print(f"[bold]First Seen:[/bold] {host.first_seen}")
    console.print(f"[bold]Last Seen:[/bold] {host.last_seen}")
    console.print(f"[bold]Scan Count:[/bold] {host.scan_count}")
    
    if host.ports:
        console.print(f"[bold]Ports:[/bold] {', '.join(map(str, host.ports))}")
    
    if host.hostnames:
        console.print(f"[bold]Hostnames:[/bold] {', '.join(host.hostnames)}")
    
    if host.jarm:
        console.print(f"[bold]JARM:[/bold] {host.jarm}")
    
    if host.cert_subject:
        console.print()
        console.print("[bold]Certificate:[/bold]")
        console.print(f"  Subject: {host.cert_subject}")
        console.print(f"  Issuer: {host.cert_issuer}")
        console.print(f"  Fingerprint: {host.cert_fingerprint}")
        console.print(f"  Self-signed: {host.cert_self_signed}")
        if host.cert_not_before:
            console.print(f"  Valid: {host.cert_not_before} - {host.cert_not_after}")
    
    if host.http_status:
        console.print()
        console.print("[bold]HTTP:[/bold]")
        console.print(f"  Status: {host.http_status}")
        console.print(f"  Server: {host.http_server or 'Not disclosed'}")
        if host.http_body_hash:
            console.print(f"  Body Hash: {host.http_body_hash}")
    
    # Show matches
    matches = session.query(Match).filter_by(host_id=host.id).all()
    if matches:
        console.print()
        console.print("[bold]Pattern Matches:[/bold]")
        for m in matches:
            actor = m.pattern.actor.name if m.pattern.actor else "Unattributed"
            console.print(f"  • {m.pattern.name} ({actor}) - {m.status}")
    
    session.close()


# =====================
# Actor Commands
# =====================

@cli.group('actor')
def actor_group():
    """Manage threat actors."""
    pass


@actor_group.command('list')
@click.pass_context
def list_actors(ctx):
    """List threat actors."""
    session = get_session(get_engine(ctx.obj['db_url']))
    
    actors = session.query(Actor).all()
    
    table = Table(title="Threat Actors")
    table.add_column("ID", style="dim")
    table.add_column("Name", style="cyan")
    table.add_column("Country")
    table.add_column("Confidence")
    table.add_column("Patterns", justify="right")
    table.add_column("Active")
    
    for a in actors:
        pattern_count = len(a.patterns)
        table.add_row(
            str(a.id),
            a.name,
            a.country or "-",
            a.confidence,
            str(pattern_count),
            "✓" if a.active else "✗"
        )
    
    console.print(table)
    session.close()


@actor_group.command('add')
@click.option('--name', required=True, help='Actor name')
@click.option('--country', help='Country code (e.g., RU, CN, KP)')
@click.option('--aliases', help='Comma-separated aliases')
@click.option('--description', help='Description')
@click.pass_context
def add_actor(ctx, name, country, aliases, description):
    """Add a new threat actor."""
    session = get_session(get_engine(ctx.obj['db_url']))
    
    alias_list = [a.strip() for a in aliases.split(',')] if aliases else []
    
    actor = Actor(
        name=name,
        country=country,
        aliases=alias_list,
        description=description,
    )
    session.add(actor)
    session.commit()
    
    console.print(f"[green]✓[/green] Added actor: {name} (ID: {actor.id})")
    session.close()


# =====================
# Stats Command
# =====================

@cli.command('stats')
@click.pass_context
def show_stats(ctx):
    """Show database statistics."""
    session = get_session(get_engine(ctx.obj['db_url']))
    
    actors = session.query(Actor).count()
    patterns = session.query(Pattern).count()
    enabled_patterns = session.query(Pattern).filter_by(enabled=True).count()
    hosts = session.query(Host).count()
    matches = session.query(Match).count()
    new_matches = session.query(Match).filter_by(status='new').count()
    
    # Recent activity
    last_24h = datetime.utcnow() - timedelta(hours=24)
    recent_hosts = session.query(Host).filter(Host.first_seen >= last_24h).count()
    recent_matches = session.query(Match).filter(Match.matched_at >= last_24h).count()
    
    console.print(Panel("[bold]Infrastructure Hunter Statistics[/bold]"))
    console.print(f"[bold]Actors:[/bold] {actors}")
    console.print(f"[bold]Patterns:[/bold] {patterns} ({enabled_patterns} enabled)")
    console.print(f"[bold]Hosts:[/bold] {hosts}")
    console.print(f"[bold]Matches:[/bold] {matches} ({new_matches} new)")
    console.print()
    console.print("[bold]Last 24 hours:[/bold]")
    console.print(f"  New hosts: {recent_hosts}")
    console.print(f"  New matches: {recent_matches}")
    
    session.close()


if __name__ == '__main__':
    cli()
