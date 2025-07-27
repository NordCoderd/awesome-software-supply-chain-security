# Dependency Confusion Finder

Generate or use an existing CycloneDX SBOM to detect dependency confusion.

## Usage
`dependency-confusion-finder.py --directory <dir> [--sbom-in <file>] [--sbom-out <file>] [--report-out <file>]`  

## Examples

```
dependency-confusion-finder.py --directory ./my-project --report-out report.txt
dependency-confusion-finder.py --sbom-in existing-sbom.json --report-out report.txt
dependency-confusion-finder.py -h
```

## Arguments

- `-h, --help` — show this help message and exit  
- `--directory <dir>` — Directory to scan (project source or container filesystem mount). Generates SBOM when provided.  
- `--sbom-in <file>` — Path to an existing CycloneDX SBOM JSON file. Skips SBOM generation.  
- `--sbom-out <file>` *(default: `sbom.json`)* — Output path for the generated SBOM JSON.  
- `--report-out <file>` *(default: `dependency_confusion_report.txt`)* — Output path for the dependency confusion report.