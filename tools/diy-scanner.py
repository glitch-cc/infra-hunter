#!/usr/bin/env python3
"""
Infrastructure Hunter - DIY Scanner
Scans IPs for C2 indicators using free/open-source tools

Usage:
    python3 diy-scanner.py <ip_or_file>
    python3 diy-scanner.py --port 50050 --count 10  # scan random port 50050 hosts
"""

import subprocess
import json
import sys
import ssl
import socket
import hashlib
from pathlib import Path

# JARM scanner path
JARM_PATH = Path(__file__).parent / "jarm" / "jarm.py"

def get_jarm(ip: str, port: int = 443) -> str:
    """Get JARM fingerprint using Salesforce scanner"""
    try:
        result = subprocess.run(
            ["python3", str(JARM_PATH), ip, "-p", str(port)],
            capture_output=True, text=True, timeout=30
        )
        for line in result.stdout.split('\n'):
            if 'JARM:' in line:
                return line.split('JARM:')[1].strip()
    except Exception as e:
        return f"error: {e}"
    return "timeout"

def get_ssl_cert(ip: str, port: int = 443) -> dict:
    """Get SSL certificate details"""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((ip, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                # Get fingerprint
                sha256 = hashlib.sha256(cert).hexdigest()
                
                # Try to get readable cert info
                cert_dict = ssock.getpeercert()
                
                return {
                    "sha256": sha256,
                    "subject": cert_dict.get('subject', []),
                    "issuer": cert_dict.get('issuer', []),
                    "notBefore": cert_dict.get('notBefore'),
                    "notAfter": cert_dict.get('notAfter'),
                }
    except Exception as e:
        return {"error": str(e)}

def get_http_headers(ip: str, port: int = 443) -> dict:
    """Get HTTP response headers"""
    import urllib.request
    import urllib.error
    
    try:
        proto = "https" if port in [443, 8443, 4443] else "http"
        url = f"{proto}://{ip}:{port}/"
        
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
            return {
                "status": response.status,
                "headers": dict(response.headers),
                "content_length": response.headers.get('Content-Length'),
                "server": response.headers.get('Server'),
            }
    except urllib.error.HTTPError as e:
        return {"status": e.code, "error": str(e.reason)}
    except Exception as e:
        return {"error": str(e)}

def scan_ip(ip: str, ports: list = [443, 50050, 8443, 4443]) -> dict:
    """Full scan of an IP"""
    results = {"ip": ip, "ports": {}}
    
    for port in ports:
        port_results = {}
        
        # JARM
        print(f"  [{port}] Getting JARM...", end=" ", flush=True)
        port_results["jarm"] = get_jarm(ip, port)
        print(port_results["jarm"][:20] + "..." if len(port_results.get("jarm", "")) > 20 else port_results.get("jarm", ""))
        
        # SSL Cert (for TLS ports)
        if port in [443, 8443, 4443, 50050]:
            print(f"  [{port}] Getting SSL cert...", end=" ", flush=True)
            cert = get_ssl_cert(ip, port)
            port_results["ssl"] = cert
            print(cert.get("sha256", cert.get("error", ""))[:20] + "...")
        
        # HTTP
        print(f"  [{port}] Getting HTTP...", end=" ", flush=True)
        http = get_http_headers(ip, port)
        port_results["http"] = http
        print(f"status={http.get('status', http.get('error', ''))}")
        
        results["ports"][port] = port_results
    
    return results


# Known C2 JARM fingerprints for comparison
KNOWN_C2_JARMS = {
    "07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2": "Cobalt Strike (Java 11)",
    "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1": "Cobalt Strike (default)",
    "2ad2ad16d2ad2ad00042d42d00042d9f78fcc5b56dd63082f95f95e89f3a3e": "Sliver",
    "2ad2ad0002ad2ad0002ad2ad2ad2ada4e3e9b8f8a3e4b6e6f4d2c5b1a0": "Mythic",
    "29d21b20d29d29d21c41d21b21b41d494e0df9532e75299f15ba73156cee38": "Metasploit",
    "3fd3fd00000000000043d43d00043de9480c702b80472d742fb4b3715a8cb1": "Port 50050 cluster (detected 2026-02-08)",
}


def check_known_jarm(jarm: str) -> str:
    """Check if JARM matches known C2"""
    return KNOWN_C2_JARMS.get(jarm, "Unknown")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    
    target = sys.argv[1]
    
    # Check if file or single IP
    if Path(target).exists():
        with open(target) as f:
            ips = [line.strip() for line in f if line.strip()]
    else:
        ips = [target]
    
    print(f"Scanning {len(ips)} IP(s)...")
    print("=" * 60)
    
    all_results = []
    for ip in ips:
        print(f"\n[*] Scanning {ip}")
        result = scan_ip(ip)
        all_results.append(result)
        
        # Check JARM against known C2
        for port, data in result["ports"].items():
            jarm = data.get("jarm", "")
            match = check_known_jarm(jarm)
            if match != "Unknown":
                print(f"  ⚠️  JARM MATCH: {match}")
    
    # Save results
    output_file = Path(__file__).parent.parent / "scan-results" / "diy-scan-latest.json"
    output_file.parent.mkdir(exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(all_results, f, indent=2)
    print(f"\n[+] Results saved to {output_file}")
