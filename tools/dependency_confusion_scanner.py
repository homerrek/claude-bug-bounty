#!/usr/bin/env python3
"""
dependency_confusion_scanner.py — Dependency confusion attack scanner.

Tests for internal package names that could be hijacked via public repos.
Scans package manifests (package.json, requirements.txt, go.mod, Gemfile, etc.)
and checks if internal packages exist on public registries.

Usage:
  python3 tools/dependency_confusion_scanner.py --url https://target.com [--depth 2]
  python3 tools/dependency_confusion_scanner.py --file package.json
  python3 tools/dependency_confusion_scanner.py --github org/repo
"""

import argparse
import json
import re
import sys
import time
import urllib.request
import urllib.error
import urllib.parse

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

FINDINGS = []
REQUEST_INTERVAL = 1.0


def _sleep():
    time.sleep(REQUEST_INTERVAL)


def _request(url, timeout=15):
    headers = {"User-Agent": "Mozilla/5.0 (compatible; BugBountyScanner/1.0)"}
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return 0, str(e)


def _add_finding(severity, title, detail, evidence=""):
    f = {"severity": severity, "title": title, "detail": detail, "evidence": evidence}
    FINDINGS.append(f)
    color = RED if severity == "CRITICAL" else YELLOW if severity == "HIGH" else CYAN
    print(f"{color}[{severity}]{RESET} {title}")
    if detail:
        print(f"  {DIM}{detail}{RESET}")
    if evidence:
        print(f"  {BLUE}Evidence: {evidence}{RESET}")


def check_npm_package(package_name):
    """Check if package exists on npmjs.org"""
    _sleep()
    status, body = _request(f"https://registry.npmjs.org/{package_name}")
    return status == 200


def check_pypi_package(package_name):
    """Check if package exists on PyPI"""
    _sleep()
    status, body = _request(f"https://pypi.org/pypi/{package_name}/json")
    return status == 200


def check_rubygems_package(package_name):
    """Check if package exists on RubyGems"""
    _sleep()
    status, body = _request(f"https://rubygems.org/api/v1/gems/{package_name}.json")
    return status == 200


def extract_packages_from_manifest(content, file_type):
    """Extract package names from manifest file content"""
    packages = []

    if file_type == "package.json":
        try:
            data = json.loads(content)
            for section in ["dependencies", "devDependencies", "peerDependencies"]:
                if section in data:
                    packages.extend(data[section].keys())
        except json.JSONDecodeError:
            pass

    elif file_type == "requirements.txt":
        # Extract package names from requirements.txt format
        for line in content.split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                # Extract package name (before ==, >=, etc.)
                match = re.match(r"^([a-zA-Z0-9_\-]+)", line)
                if match:
                    packages.append(match.group(1))

    elif file_type == "Gemfile":
        # Extract gem names from Gemfile
        for line in content.split("\n"):
            match = re.search(r"gem\s+['\"]([^'\"]+)['\"]", line)
            if match:
                packages.append(match.group(1))

    elif file_type == "go.mod":
        # Extract module names from go.mod
        in_require = False
        for line in content.split("\n"):
            if line.strip().startswith("require"):
                in_require = True
            elif in_require:
                if line.strip() == ")":
                    in_require = False
                else:
                    match = re.match(r"\s*([^\s]+)", line.strip())
                    if match:
                        packages.append(match.group(1))

    return packages


def identify_internal_packages(packages):
    """Heuristic to identify potentially internal packages"""
    internal_indicators = [
        r"^@[a-zA-Z0-9\-]+/",  # Scoped npm packages
        r"^internal-",
        r"^private-",
        r"^company-",
        r"^corp-",
        r"-internal$",
        r"-private$",
    ]

    internal_packages = []
    for pkg in packages:
        for pattern in internal_indicators:
            if re.search(pattern, pkg, re.IGNORECASE):
                internal_packages.append(pkg)
                break

    return internal_packages


def scan_file(file_path, file_type=None):
    """Scan a local manifest file"""
    print(f"\n{BOLD}Dependency Confusion Scanner{RESET}")
    print(f"Scanning file: {file_path}\n")

    if not file_type:
        if "package.json" in file_path:
            file_type = "package.json"
        elif "requirements.txt" in file_path:
            file_type = "requirements.txt"
        elif "Gemfile" in file_path:
            file_type = "Gemfile"
        elif "go.mod" in file_path:
            file_type = "go.mod"
        else:
            print(f"{RED}[ERROR] Unknown file type. Use --type to specify.{RESET}")
            return

    try:
        with open(file_path, "r") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"{RED}[ERROR] File not found: {file_path}{RESET}")
        return

    packages = extract_packages_from_manifest(content, file_type)
    print(f"Found {len(packages)} total packages")

    internal_packages = identify_internal_packages(packages)
    print(f"Identified {len(internal_packages)} potentially internal packages\n")

    if not internal_packages:
        print(f"{GREEN}No internal packages detected. Low risk.{RESET}")
        return

    print(f"{BOLD}Checking public registry availability...{RESET}\n")

    for pkg in internal_packages:
        # Determine which registry to check based on file type
        exists = False
        registry = ""

        if file_type == "package.json":
            exists = check_npm_package(pkg)
            registry = "npm"
        elif file_type == "requirements.txt":
            exists = check_pypi_package(pkg)
            registry = "PyPI"
        elif file_type == "Gemfile":
            exists = check_rubygems_package(pkg)
            registry = "RubyGems"

        if not exists:
            _add_finding("CRITICAL",
                        f"Dependency confusion vulnerability: {pkg}",
                        f"Internal package NOT found on public {registry} — can be hijacked!",
                        f"Package: {pkg}, Registry: {registry}")
        else:
            print(f"{YELLOW}[INFO] {pkg} already exists on {registry} (protected){RESET}")


def scan_github_repo(repo):
    """Scan manifest files from a GitHub repository"""
    print(f"\n{BOLD}Dependency Confusion Scanner{RESET}")
    print(f"Scanning GitHub repo: {repo}\n")

    manifest_files = [
        ("package.json", "package.json"),
        ("requirements.txt", "requirements.txt"),
        ("Gemfile", "Gemfile"),
        ("go.mod", "go.mod"),
    ]

    for filename, file_type in manifest_files:
        url = f"https://raw.githubusercontent.com/{repo}/main/{filename}"
        status, content = _request(url)

        if status == 200:
            print(f"\n{BOLD}Found {filename}{RESET}")
            packages = extract_packages_from_manifest(content, file_type)
            internal_packages = identify_internal_packages(packages)

            if internal_packages:
                print(f"Potentially internal packages: {len(internal_packages)}")
                for pkg in internal_packages[:5]:  # Limit output
                    print(f"  - {pkg}")
                if len(internal_packages) > 5:
                    print(f"  ... and {len(internal_packages) - 5} more")


def main():
    parser = argparse.ArgumentParser(description="Dependency confusion scanner")
    parser.add_argument("--file", help="Local manifest file to scan")
    parser.add_argument("--type", choices=["package.json", "requirements.txt", "Gemfile", "go.mod"],
                       help="Manifest file type")
    parser.add_argument("--github", help="GitHub repo (format: org/repo)")
    parser.add_argument("--rate", type=float, default=1.0, help="Requests per second")
    parser.add_argument("--json", dest="json_out", action="store_true", help="JSON output")
    args = parser.parse_args()

    global REQUEST_INTERVAL
    REQUEST_INTERVAL = 1.0 / args.rate if args.rate > 0 else 1.0

    if args.file:
        scan_file(args.file, args.type)
    elif args.github:
        scan_github_repo(args.github)
    else:
        print(f"{RED}[ERROR] Provide --file or --github{RESET}")
        sys.exit(1)

    if args.json_out:
        print(json.dumps({"findings": FINDINGS}, indent=2))
    else:
        print(f"\n{BOLD}Summary: {len(FINDINGS)} critical finding(s){RESET}")
        if FINDINGS:
            print(f"{RED}VULNERABLE: Internal packages can be hijacked via public registries!{RESET}")
        else:
            print(f"{GREEN}No dependency confusion vulnerabilities detected.{RESET}")


if __name__ == "__main__":
    main()
