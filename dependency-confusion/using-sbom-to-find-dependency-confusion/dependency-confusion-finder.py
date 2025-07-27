import argparse
import json
import subprocess
import sys
from pathlib import Path
import requests


def check_trivy():
    """Ensure Trivy is installed and on PATH."""
    try:
        subprocess.run(["trivy", "--version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: Trivy is not installed or not on your PATH.", file=sys.stderr)
        sys.exit(1)


def generate_sbom(target_dir: Path, sbom_path: Path):
    """Generate a CycloneDX SBOM JSON using Trivy for the given directory."""
    cmd = ["trivy", "fs", "--format", "cyclonedx", "-o", str(sbom_path), str(target_dir)]
    print(f"Generating SBOM -> {sbom_path}")
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error: Trivy SBOM generation failed (exit code {e.returncode}).", file=sys.stderr)
        sys.exit(e.returncode)


def parse_purls(sbom_path: Path):
    """Parse unique purl entries from a CycloneDX SBOM JSON file."""
    try:
        with sbom_path.open() as f:
            data = json.load(f)
        components = data.get("components", [])
        return sorted({comp.get("purl") for comp in components if comp.get("purl")})
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error: Failed to parse SBOM file '{sbom_path}': {e}", file=sys.stderr)
        sys.exit(1)


def extract_pkg_info(purl: str):
    """Extract the ecosystem (e.g., 'pypi', 'npm') and package name from a purl string."""
    try:
        _, rest = purl.split(":", 1)
        ecosystem, remainder = rest.split("/", 1)
        pkg_name = remainder.split("@", 1)[0]
        return ecosystem, pkg_name
    except ValueError:
        return None, None


def check_public_registry(ecosystem: str, name: str):
    """Check if a package exists on its public registry: returns True if exists, False if not, None on error/unsupported."""
    try:
        if ecosystem == "pypi":
            url = f"https://pypi.org/pypi/{name}/json"
        elif ecosystem == "npm":
            url = f"https://registry.npmjs.org/{name}"
        else:
            return None
        resp = requests.get(url, timeout=10)
        if resp.status_code == 404:
            return False
        if resp.status_code == 200:
            return True
        print(f"Warning: Unexpected status {resp.status_code} for {ecosystem}/{name}", file=sys.stderr)
        return None
    except requests.RequestException as e:
        print(f"Error: Network error when checking {ecosystem}/{name}: {e}", file=sys.stderr)
        return None


def main():
    usage_text = '''
dependency-confusion-finder.py --directory <dir> [--sbom-in <file>] [--sbom-out <file>] [--report-out <file>]
Generate or use an existing CycloneDX SBOM to detect dependency confusion.

Examples:
  dependency-confusion-finder.py --directory ./my-project --report-out report.txt
  dependency-confusion-finder.py --sbom-in existing-sbom.json --report-out report.txt
  dependency-confusion-finder.py -h
'''  # noqa: E501

    parser = argparse.ArgumentParser(
        description="Detect potential dependency confusion using CycloneDX SBOMs",
        usage=usage_text,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exit codes: 0=success, >0=error"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--directory",
        type=Path,
        help="Directory to scan: project source or container filesystem mount. Generates SBOM when provided."
    )
    group.add_argument(
        "--sbom-in",
        type=Path,
        help="Path to an existing CycloneDX SBOM JSON file. Skips SBOM generation."
    )
    parser.add_argument(
        "--sbom-out",
        type=Path,
        default=Path("sbom.json"),
        help="Output path for the generated SBOM JSON (default: sbom.json)."
    )
    parser.add_argument(
        "--report-out",
        type=Path,
        default=Path("dependency_confusion_report.txt"),
        help="Output path for the dependency confusion report (default: dependency_confusion_report.txt)."
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    # Determine SBOM source
    if args.sbom_in:
        sbom_path = args.sbom_in
    else:
        check_trivy()
        generate_sbom(args.directory, args.sbom_out)
        sbom_path = args.sbom_out

    # Parse PURLs
    purls = parse_purls(sbom_path)
    if not purls:
        print("No PURLs found in SBOM.", file=sys.stderr)

    # Check public registries and build report
    report_lines = []
    for purl in purls:
        eco, name = extract_pkg_info(purl)
        if not eco or not name:
            print(f"Skipping invalid PURL: {purl}", file=sys.stderr)
            continue
        exists = check_public_registry(eco, name)
        if exists is False:
            report_lines.append(f"[OK]   {eco:<5} {name} not found publicly")
        elif exists is True:
            report_lines.append(f"[WARN] {eco:<5} {name} EXISTS publicly - potential collision")
        else:
            report_lines.append(f"[INFO] {eco:<5} {name} unknown status or unsupported ecosystem")

    # Write report to file
    try:
        with args.report_out.open("w") as f:
            f.write("\n".join(report_lines))
        print(f"Dependency confusion report written to {args.report_out}")
    except Exception as e:
        print(f"Error: Unable to write report file '{args.report_out}': {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
