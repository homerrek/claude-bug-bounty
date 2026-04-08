#!/usr/bin/env python3
"""
kali_integration.py — Kali Linux tool orchestrator and integration layer.

Provides unified interface for running Kali security tools with proper
configuration, output parsing, and finding aggregation.

Usage:
  python3 tools/kali_integration.py --target target.com --profile web
  python3 tools/kali_integration.py --target target.com --tools nmap,nikto,sqlmap
  python3 tools/kali_integration.py --list-tools
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

FINDINGS = []
TOOL_OUTPUTS = {}

# Tool profiles for different hunting scenarios
TOOL_PROFILES = {
    "web": ["nmap", "nikto", "whatweb", "wpscan", "sqlmap", "dirb"],
    "network": ["nmap", "masscan", "netdiscover", "arp-scan"],
    "wireless": ["aircrack-ng", "reaver", "wifite"],
    "webapp": ["burpsuite", "zaproxy", "sqlmap", "nikto", "wpscan", "dirb", "gobuster"],
    "password": ["john", "hashcat", "hydra", "medusa", "ncrack"],
    "exploitation": ["metasploit", "searchsploit", "exploit-db"],
    "enumeration": ["enum4linux", "smbclient", "rpcclient", "ldapsearch"],
    "full": ["nmap", "nikto", "dirb", "sqlmap", "whatweb", "enum4linux"]
}

# Tool configurations
TOOL_CONFIGS = {
    "nmap": {
        "cmd": "nmap",
        "args": ["-sV", "-sC", "-O", "--script=vuln"],
        "timeout": 300,
        "output_file": "nmap_scan.txt"
    },
    "nikto": {
        "cmd": "nikto",
        "args": ["-h"],
        "timeout": 600,
        "output_file": "nikto_scan.txt"
    },
    "sqlmap": {
        "cmd": "sqlmap",
        "args": ["-u", "--batch", "--random-agent"],
        "timeout": 900,
        "output_file": "sqlmap_scan.txt"
    },
    "dirb": {
        "cmd": "dirb",
        "args": [],
        "timeout": 300,
        "output_file": "dirb_scan.txt"
    },
    "gobuster": {
        "cmd": "gobuster",
        "args": ["dir", "-u", "-w", "/usr/share/wordlists/dirb/common.txt"],
        "timeout": 300,
        "output_file": "gobuster_scan.txt"
    },
    "whatweb": {
        "cmd": "whatweb",
        "args": ["-a", "3"],
        "timeout": 60,
        "output_file": "whatweb_scan.txt"
    },
    "wpscan": {
        "cmd": "wpscan",
        "args": ["--url", "--enumerate", "vp,vt,u"],
        "timeout": 600,
        "output_file": "wpscan_scan.txt"
    },
    "enum4linux": {
        "cmd": "enum4linux",
        "args": ["-a"],
        "timeout": 300,
        "output_file": "enum4linux_scan.txt"
    }
}


def _add_finding(severity, title, detail, evidence="", tool=""):
    f = {
        "severity": severity,
        "title": title,
        "detail": detail,
        "evidence": evidence,
        "tool": tool
    }
    FINDINGS.append(f)
    color = RED if severity == "CRITICAL" else YELLOW if severity == "HIGH" else CYAN
    print(f"{color}[{severity}]{RESET} {title}")
    if detail:
        print(f"  {DIM}{detail}{RESET}")
    if evidence:
        print(f"  {BLUE}Evidence: {evidence}{RESET}")
    if tool:
        print(f"  {CYAN}Tool: {tool}{RESET}")


def check_tool_installed(tool_name):
    """Check if a Kali tool is installed"""
    try:
        result = subprocess.run(["which", tool_name], capture_output=True, timeout=5)
        return result.returncode == 0
    except Exception:
        return False


def run_tool(tool_name, target, output_dir):
    """Run a Kali tool with proper configuration"""
    if tool_name not in TOOL_CONFIGS:
        print(f"{YELLOW}[WARNING] No configuration for {tool_name}{RESET}")
        return None

    if not check_tool_installed(tool_name):
        print(f"{RED}[ERROR] {tool_name} not installed{RESET}")
        return None

    config = TOOL_CONFIGS[tool_name]
    output_file = os.path.join(output_dir, config["output_file"])

    # Build command
    cmd = [config["cmd"]]

    # Add args with target substitution
    for arg in config["args"]:
        if arg in ["-h", "-u", "--url"]:
            cmd.append(arg)
            cmd.append(target)
        else:
            cmd.append(arg)

    # For tools without explicit target flag
    if tool_name in ["nmap", "dirb", "whatweb", "enum4linux"]:
        if target not in cmd:
            cmd.append(target)

    print(f"\n{BOLD}Running {tool_name}...{RESET}")
    print(f"{DIM}Command: {' '.join(cmd)}{RESET}\n")

    try:
        start_time = time.time()
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config["timeout"]
        )
        elapsed = time.time() - start_time

        # Save output
        with open(output_file, "w") as f:
            f.write(f"Command: {' '.join(cmd)}\n")
            f.write(f"Exit code: {result.returncode}\n")
            f.write(f"Elapsed: {elapsed:.2f}s\n\n")
            f.write("=== STDOUT ===\n")
            f.write(result.stdout)
            f.write("\n=== STDERR ===\n")
            f.write(result.stderr)

        TOOL_OUTPUTS[tool_name] = {
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "elapsed": elapsed,
            "output_file": output_file
        }

        if result.returncode == 0:
            print(f"{GREEN}[OK] {tool_name} completed in {elapsed:.2f}s{RESET}")
        else:
            print(f"{YELLOW}[WARNING] {tool_name} exited with code {result.returncode}{RESET}")

        return result.stdout

    except subprocess.TimeoutExpired:
        print(f"{RED}[TIMEOUT] {tool_name} exceeded {config['timeout']}s{RESET}")
        return None
    except Exception as e:
        print(f"{RED}[ERROR] {tool_name} failed: {e}{RESET}")
        return None


def parse_nmap_output(output):
    """Parse nmap output for findings"""
    if not output:
        return

    lines = output.split("\n")
    for line in lines:
        if "open" in line.lower() and "port" in line.lower():
            _add_finding("MEDIUM", f"Open port detected", line.strip(), tool="nmap")
        if "vulnerable" in line.lower() or "vuln" in line.lower():
            _add_finding("HIGH", "Vulnerability detected by nmap", line.strip(), tool="nmap")


def parse_nikto_output(output):
    """Parse nikto output for findings"""
    if not output:
        return

    lines = output.split("\n")
    for line in lines:
        if "+ OSVDB" in line or "+ " in line:
            if any(keyword in line.lower() for keyword in ["vulnerability", "disclosure", "exploit"]):
                _add_finding("HIGH", "Nikto vulnerability", line.strip(), tool="nikto")
            elif "version" in line.lower() or "header" in line.lower():
                _add_finding("MEDIUM", "Nikto info disclosure", line.strip(), tool="nikto")


def parse_sqlmap_output(output):
    """Parse sqlmap output for findings"""
    if not output:
        return

    if "is vulnerable" in output or "sqlmap identified" in output:
        _add_finding("CRITICAL", "SQL injection detected", "SQLMap found injectable parameter", tool="sqlmap")
    if "parameter" in output.lower() and "injectable" in output.lower():
        _add_finding("CRITICAL", "SQL injection", "Injectable parameter found", tool="sqlmap")


def parse_tool_output(tool_name, output):
    """Route output to appropriate parser"""
    if not output:
        return

    parsers = {
        "nmap": parse_nmap_output,
        "nikto": parse_nikto_output,
        "sqlmap": parse_sqlmap_output,
    }

    parser = parsers.get(tool_name)
    if parser:
        parser(output)


def list_available_tools():
    """List all available Kali tools and their status"""
    print(f"\n{BOLD}Available Kali Tools{RESET}\n")

    print(f"{BOLD}Tool Profiles:{RESET}")
    for profile, tools in TOOL_PROFILES.items():
        print(f"  {CYAN}{profile}{RESET}: {', '.join(tools)}")

    print(f"\n{BOLD}Individual Tools:{RESET}")
    for tool_name in sorted(TOOL_CONFIGS.keys()):
        installed = check_tool_installed(tool_name)
        status = f"{GREEN}✓ installed{RESET}" if installed else f"{RED}✗ not found{RESET}"
        print(f"  {tool_name}: {status}")


def main():
    parser = argparse.ArgumentParser(description="Kali Linux tool integration")
    parser.add_argument("--target", help="Target URL or IP")
    parser.add_argument("--profile", choices=TOOL_PROFILES.keys(), help="Tool profile to run")
    parser.add_argument("--tools", help="Comma-separated list of tools to run")
    parser.add_argument("--output-dir", default="./kali_output", help="Output directory")
    parser.add_argument("--list-tools", action="store_true", help="List available tools")
    parser.add_argument("--json", dest="json_out", action="store_true", help="JSON output")
    args = parser.parse_args()

    if args.list_tools:
        list_available_tools()
        return

    if not args.target:
        print(f"{RED}[ERROR] --target required (or use --list-tools){RESET}")
        sys.exit(1)

    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{BOLD}Kali Linux Tool Integration{RESET}")
    print(f"Target: {args.target}")
    print(f"Output: {output_dir}\n")

    # Determine which tools to run
    tools_to_run = []
    if args.profile:
        tools_to_run = TOOL_PROFILES[args.profile]
        print(f"Profile: {args.profile}")
    elif args.tools:
        tools_to_run = [t.strip() for t in args.tools.split(",")]
    else:
        print(f"{RED}[ERROR] Provide --profile or --tools{RESET}")
        sys.exit(1)

    print(f"Tools: {', '.join(tools_to_run)}\n")

    # Run each tool
    for tool_name in tools_to_run:
        output = run_tool(tool_name, args.target, output_dir)
        if output:
            parse_tool_output(tool_name, output)

    # Summary
    if args.json_out:
        output = {
            "findings": FINDINGS,
            "tool_outputs": {
                name: {
                    "exit_code": data["exit_code"],
                    "elapsed": data["elapsed"],
                    "output_file": data["output_file"]
                }
                for name, data in TOOL_OUTPUTS.items()
            }
        }
        print(json.dumps(output, indent=2))
    else:
        print(f"\n{BOLD}Summary:{RESET}")
        print(f"  Tools run: {len(TOOL_OUTPUTS)}")
        print(f"  Findings: {len(FINDINGS)}")
        print(f"  Output: {output_dir}\n")

        if FINDINGS:
            print(f"{BOLD}Findings by severity:{RESET}")
            critical = len([f for f in FINDINGS if f["severity"] == "CRITICAL"])
            high = len([f for f in FINDINGS if f["severity"] == "HIGH"])
            medium = len([f for f in FINDINGS if f["severity"] == "MEDIUM"])
            print(f"  {RED}CRITICAL: {critical}{RESET}")
            print(f"  {YELLOW}HIGH: {high}{RESET}")
            print(f"  {CYAN}MEDIUM: {medium}{RESET}")


if __name__ == "__main__":
    main()
