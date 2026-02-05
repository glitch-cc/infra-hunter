#!/usr/bin/env python3
"""
Signature Manager - Load, validate, create, and manage YAML-based signatures.
"""
import os
import re
import yaml
from pathlib import Path
from datetime import datetime, date
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
import json


LIBRARY_PATH = Path(__file__).parent / "library"
SIGNATURE_SCHEMA_VERSION = "1.0"

# Valid values for enum fields
CATEGORIES = ["c2-frameworks", "apt-infrastructure", "ransomware", "phishing", "generic"]
CONFIDENCE_LEVELS = ["high", "medium", "low"]
SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]
MATCH_TYPES = ["any", "all"]
CONDITION_TYPES = [
    "cert_fingerprint", "cert_field", "cert_subject", "cert_issuer",
    "jarm", "http_header", "http_status", "http_body_hash",
    "port", "asn", "hostname", "banner", "regex"
]
OPERATORS = ["equals", "contains", "regex", "gt", "lt", "in", "not_equals"]


@dataclass
class Condition:
    """A single detection condition."""
    name: str
    type: str
    field: str
    operator: str
    value: Any
    weight: int = 50
    note: Optional[str] = None
    
    def to_dict(self) -> dict:
        d = {
            "name": self.name,
            "type": self.type,
            "field": self.field,
            "operator": self.operator,
            "value": self.value,
            "weight": self.weight,
        }
        if self.note:
            d["note"] = self.note
        return d
    
    @classmethod
    def from_dict(cls, data: dict) -> "Condition":
        return cls(
            name=data["name"],
            type=data["type"],
            field=data["field"],
            operator=data.get("operator", "equals"),
            value=data["value"],
            weight=data.get("weight", 50),
            note=data.get("note"),
        )
    
    def to_censys_query(self) -> Optional[str]:
        """Generate Censys query fragment for this condition."""
        if self.operator == "equals":
            return f'{self.field}:"{self.value}"'
        elif self.operator == "contains":
            return f'{self.field}:*{self.value}*'
        elif self.operator == "regex":
            return f'{self.field}:/{self.value}/'
        return None


@dataclass
class Signature:
    """A complete detection signature."""
    id: str
    name: str
    version: str
    category: str
    description: str
    logic_match: str  # "any" or "all"
    conditions: List[Condition]
    
    # Optional fields
    author: Optional[str] = None
    attribution_actors: List[str] = field(default_factory=list)
    attribution_confidence: str = "low"
    attribution_note: Optional[str] = None
    
    confidence: str = "medium"
    severity: str = "medium"
    false_positive_rate: str = "medium"
    last_verified: Optional[str] = None
    
    queries_censys: Optional[str] = None
    queries_shodan: Optional[str] = None
    
    references: List[Dict[str, str]] = field(default_factory=list)
    enabled: bool = True
    changelog: List[Dict[str, str]] = field(default_factory=list)
    
    # Computed
    file_path: Optional[Path] = None
    
    def to_dict(self) -> dict:
        """Convert to YAML-serializable dict."""
        sig = {
            "signature": {
                "id": self.id,
                "name": self.name,
                "version": self.version,
                "category": self.category,
                "description": self.description,
                "logic": {
                    "match": self.logic_match,
                    "conditions": [c.to_dict() for c in self.conditions],
                },
                "metadata": {
                    "confidence": self.confidence,
                    "severity": self.severity,
                    "false_positive_rate": self.false_positive_rate,
                },
                "enabled": self.enabled,
            }
        }
        
        if self.author:
            sig["signature"]["author"] = self.author
        
        if self.attribution_actors:
            sig["signature"]["attribution"] = {
                "actors": self.attribution_actors,
                "confidence": self.attribution_confidence,
            }
            if self.attribution_note:
                sig["signature"]["attribution"]["note"] = self.attribution_note
        
        if self.last_verified:
            sig["signature"]["metadata"]["last_verified"] = self.last_verified
        
        if self.queries_censys or self.queries_shodan:
            sig["signature"]["queries"] = {}
            if self.queries_censys:
                sig["signature"]["queries"]["censys"] = self.queries_censys
            if self.queries_shodan:
                sig["signature"]["queries"]["shodan"] = self.queries_shodan
        
        if self.references:
            sig["signature"]["references"] = self.references
        
        if self.changelog:
            sig["signature"]["changelog"] = self.changelog
        
        return sig
    
    @classmethod
    def from_dict(cls, data: dict, file_path: Optional[Path] = None) -> "Signature":
        """Parse from YAML dict."""
        sig = data.get("signature", data)
        
        logic = sig.get("logic", {})
        conditions = [Condition.from_dict(c) for c in logic.get("conditions", [])]
        
        meta = sig.get("metadata", {})
        attr = sig.get("attribution", {})
        queries = sig.get("queries", {})
        
        return cls(
            id=sig["id"],
            name=sig["name"],
            version=sig.get("version", "1.0.0"),
            category=sig.get("category", "generic"),
            description=sig.get("description", ""),
            logic_match=logic.get("match", "any"),
            conditions=conditions,
            author=sig.get("author"),
            attribution_actors=attr.get("actors", []),
            attribution_confidence=attr.get("confidence", "low"),
            attribution_note=attr.get("note"),
            confidence=meta.get("confidence", "medium"),
            severity=meta.get("severity", "medium"),
            false_positive_rate=meta.get("false_positive_rate", "medium"),
            last_verified=meta.get("last_verified"),
            queries_censys=queries.get("censys"),
            queries_shodan=queries.get("shodan"),
            references=sig.get("references", []),
            enabled=sig.get("enabled", True),
            changelog=sig.get("changelog", []),
            file_path=file_path,
        )
    
    def generate_censys_query(self) -> str:
        """Auto-generate Censys query from conditions."""
        parts = []
        for cond in self.conditions:
            q = cond.to_censys_query()
            if q:
                parts.append(q)
        
        if not parts:
            return ""
        
        join_op = " OR " if self.logic_match == "any" else " AND "
        return join_op.join(parts)
    
    def validate(self) -> List[str]:
        """Validate signature, return list of errors."""
        errors = []
        
        if not re.match(r'^[a-z0-9-]+$', self.id):
            errors.append(f"Invalid ID format: {self.id} (use lowercase, numbers, hyphens)")
        
        if self.category not in CATEGORIES:
            errors.append(f"Invalid category: {self.category} (valid: {CATEGORIES})")
        
        if self.confidence not in CONFIDENCE_LEVELS:
            errors.append(f"Invalid confidence: {self.confidence}")
        
        if self.severity not in SEVERITY_LEVELS:
            errors.append(f"Invalid severity: {self.severity}")
        
        if self.logic_match not in MATCH_TYPES:
            errors.append(f"Invalid match type: {self.logic_match}")
        
        if not self.conditions:
            errors.append("No conditions defined")
        
        for cond in self.conditions:
            if cond.type not in CONDITION_TYPES:
                errors.append(f"Invalid condition type: {cond.type} in {cond.name}")
            if cond.operator not in OPERATORS:
                errors.append(f"Invalid operator: {cond.operator} in {cond.name}")
            if not 0 <= cond.weight <= 100:
                errors.append(f"Weight must be 0-100: {cond.weight} in {cond.name}")
        
        return errors
    
    def summary(self) -> str:
        """One-line summary."""
        status = "✓" if self.enabled else "○"
        return f"{status} [{self.category}] {self.id} v{self.version} - {self.name} ({self.confidence} conf)"


class SignatureManager:
    """Manage signature library."""
    
    def __init__(self, library_path: Optional[Path] = None):
        self.library_path = library_path or LIBRARY_PATH
        self._signatures: Dict[str, Signature] = {}
        self._loaded = False
    
    def _ensure_loaded(self):
        if not self._loaded:
            self.load_all()
    
    def load_all(self) -> int:
        """Load all signatures from library."""
        self._signatures = {}
        count = 0
        
        if not self.library_path.exists():
            self.library_path.mkdir(parents=True, exist_ok=True)
            return 0
        
        for yaml_file in self.library_path.rglob("*.yaml"):
            if yaml_file.name == "schema.yaml":
                continue
            try:
                sig = self.load_file(yaml_file)
                if sig:
                    self._signatures[sig.id] = sig
                    count += 1
            except Exception as e:
                print(f"Error loading {yaml_file}: {e}")
        
        self._loaded = True
        return count
    
    def load_file(self, path: Path) -> Optional[Signature]:
        """Load a single signature file."""
        with open(path) as f:
            data = yaml.safe_load(f)
        
        if not data:
            return None
        
        return Signature.from_dict(data, file_path=path)
    
    def save(self, sig: Signature) -> Path:
        """Save signature to library."""
        # Determine path
        category_path = self.library_path / sig.category
        category_path.mkdir(parents=True, exist_ok=True)
        file_path = category_path / f"{sig.id}.yaml"
        
        # Add changelog entry if new or version changed
        existing = self._signatures.get(sig.id)
        if not existing or existing.version != sig.version:
            sig.changelog.insert(0, {
                "version": sig.version,
                "date": date.today().isoformat(),
                "changes": "Updated" if existing else "Initial signature",
            })
        
        # Write
        with open(file_path, 'w') as f:
            yaml.dump(sig.to_dict(), f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        
        sig.file_path = file_path
        self._signatures[sig.id] = sig
        
        return file_path
    
    def delete(self, sig_id: str) -> bool:
        """Delete a signature."""
        self._ensure_loaded()
        sig = self._signatures.get(sig_id)
        if not sig or not sig.file_path:
            return False
        
        sig.file_path.unlink(missing_ok=True)
        del self._signatures[sig_id]
        return True
    
    def get(self, sig_id: str) -> Optional[Signature]:
        """Get signature by ID."""
        self._ensure_loaded()
        return self._signatures.get(sig_id)
    
    def list(self, category: Optional[str] = None, enabled_only: bool = False) -> List[Signature]:
        """List signatures with optional filters."""
        self._ensure_loaded()
        
        sigs = list(self._signatures.values())
        
        if category:
            sigs = [s for s in sigs if s.category == category]
        
        if enabled_only:
            sigs = [s for s in sigs if s.enabled]
        
        return sorted(sigs, key=lambda s: (s.category, s.id))
    
    def search(self, query: str) -> List[Signature]:
        """Search signatures by name, id, or description."""
        self._ensure_loaded()
        query = query.lower()
        
        results = []
        for sig in self._signatures.values():
            if (query in sig.id.lower() or 
                query in sig.name.lower() or 
                query in sig.description.lower()):
                results.append(sig)
        
        return sorted(results, key=lambda s: s.id)
    
    def stats(self) -> dict:
        """Get signature statistics."""
        self._ensure_loaded()
        
        by_category = {}
        by_confidence = {"high": 0, "medium": 0, "low": 0}
        enabled = 0
        disabled = 0
        
        for sig in self._signatures.values():
            by_category[sig.category] = by_category.get(sig.category, 0) + 1
            by_confidence[sig.confidence] = by_confidence.get(sig.confidence, 0) + 1
            if sig.enabled:
                enabled += 1
            else:
                disabled += 1
        
        return {
            "total": len(self._signatures),
            "enabled": enabled,
            "disabled": disabled,
            "by_category": by_category,
            "by_confidence": by_confidence,
        }
    
    def export_to_db_format(self, sig: Signature) -> dict:
        """Export signature to infra-hunter database format."""
        # Map condition types to pattern_type
        type_map = {
            "cert_fingerprint": "cert_fingerprint",
            "cert_field": "cert_subject_dn",
            "cert_subject": "cert_subject_dn",
            "cert_issuer": "cert_issuer_dn",
            "jarm": "jarm",
            "http_header": "http_headers",
            "http_status": "http_headers",
            "asn": "asn",
            "port": "port_combo",
        }
        
        # Use first condition for primary pattern type
        primary_type = "composite"
        if sig.conditions:
            primary_type = type_map.get(sig.conditions[0].type, "composite")
        
        return {
            "name": sig.name,
            "pattern_type": primary_type,
            "definition": {
                "signature_id": sig.id,
                "match": sig.logic_match,
                "conditions": [c.to_dict() for c in sig.conditions],
            },
            "description": sig.description,
            "confidence": sig.confidence,
            "censys_query": sig.queries_censys or sig.generate_censys_query(),
            "source": sig.author or "infra-hunter signatures",
            "references": [r.get("url", "") for r in sig.references if r.get("url")],
            "enabled": sig.enabled,
        }


def create_signature_interactive() -> Signature:
    """Interactive signature creation wizard."""
    print("\n=== Create New Signature ===\n")
    
    # Basic info
    sig_id = input("Signature ID (lowercase-with-hyphens): ").strip()
    name = input("Name: ").strip()
    
    print(f"Categories: {', '.join(CATEGORIES)}")
    category = input("Category: ").strip()
    
    description = input("Description: ").strip()
    author = input("Author (optional): ").strip() or None
    
    # Detection logic
    print(f"\nMatch type: {', '.join(MATCH_TYPES)}")
    logic_match = input("Match type [any]: ").strip() or "any"
    
    conditions = []
    print("\n--- Add Conditions (empty name to finish) ---")
    while True:
        cond_name = input("\nCondition name (or Enter to finish): ").strip()
        if not cond_name:
            break
        
        print(f"Types: {', '.join(CONDITION_TYPES)}")
        cond_type = input("Type: ").strip()
        
        cond_field = input("Field (e.g., services.tls.certificates.leaf_data.fingerprint): ").strip()
        cond_value = input("Value: ").strip()
        cond_weight = int(input("Weight [50]: ").strip() or "50")
        cond_note = input("Note (optional): ").strip() or None
        
        conditions.append(Condition(
            name=cond_name,
            type=cond_type,
            field=cond_field,
            operator="equals",
            value=cond_value,
            weight=cond_weight,
            note=cond_note,
        ))
        print(f"  Added condition: {cond_name}")
    
    # Metadata
    print(f"\nConfidence levels: {', '.join(CONFIDENCE_LEVELS)}")
    confidence = input("Confidence [medium]: ").strip() or "medium"
    
    print(f"Severity levels: {', '.join(SEVERITY_LEVELS)}")
    severity = input("Severity [medium]: ").strip() or "medium"
    
    sig = Signature(
        id=sig_id,
        name=name,
        version="1.0.0",
        category=category,
        description=description,
        logic_match=logic_match,
        conditions=conditions,
        author=author,
        confidence=confidence,
        severity=severity,
        last_verified=date.today().isoformat(),
    )
    
    # Auto-generate query
    sig.queries_censys = sig.generate_censys_query()
    
    return sig


if __name__ == "__main__":
    import sys
    
    mgr = SignatureManager()
    
    if len(sys.argv) < 2:
        print("Usage: manager.py <list|stats|show|create|validate>")
        sys.exit(1)
    
    cmd = sys.argv[1]
    
    if cmd == "list":
        sigs = mgr.list()
        if not sigs:
            print("No signatures found. Run migration to import from legacy Python files.")
        for sig in sigs:
            print(sig.summary())
    
    elif cmd == "stats":
        stats = mgr.stats()
        print(json.dumps(stats, indent=2))
    
    elif cmd == "show" and len(sys.argv) > 2:
        sig = mgr.get(sys.argv[2])
        if sig:
            print(yaml.dump(sig.to_dict(), default_flow_style=False))
        else:
            print(f"Signature not found: {sys.argv[2]}")
    
    elif cmd == "create":
        sig = create_signature_interactive()
        errors = sig.validate()
        if errors:
            print(f"\nValidation errors:")
            for e in errors:
                print(f"  - {e}")
        else:
            path = mgr.save(sig)
            print(f"\nSaved to: {path}")
    
    elif cmd == "validate" and len(sys.argv) > 2:
        sig = mgr.get(sys.argv[2])
        if sig:
            errors = sig.validate()
            if errors:
                for e in errors:
                    print(f"ERROR: {e}")
            else:
                print("✓ Valid")
        else:
            print(f"Signature not found: {sys.argv[2]}")
    
    else:
        print(f"Unknown command: {cmd}")
