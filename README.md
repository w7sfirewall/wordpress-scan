# wordpress-scan

**wordpress-scan** is a Python-based static analysis tool designed to scan WordPress source code and identify HTTP mutation endpoints such as `POST`, `PUT`, and `PATCH`.  

The tool analyzes WordPress core, themes, and plugins to detect potential write operations, helping developers and security researchers understand the application's attack surface and data modification entry points.

## Requirements

- Python `3.12+`
- Dependency: `loguru==0.7.3`

Install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

## Usage (Step 1)

Run the scanner with:

```bash
python3 main.py --path <directory>
```

### CLI arguments

- `--path <directory>` (required): Directory to scan.
- `--format json|table` (optional, default: `table`): Output format.
- `--output <file_path>` (optional): Write the exact formatted output to a file (overwrite mode).
- `--verbose` (optional): Print debug information.

### Examples

```bash
# Default table output
python3 main.py --path ./wordpress

# JSON output
python3 main.py --path ./wordpress --format json

# Write output to a file
python3 main.py --path ./wordpress --output ./scan-result.txt

# Verbose mode
python3 main.py --path ./wordpress --verbose
```

### Notes

- If `--path` does not exist (or is not a directory), the program exits with code `1`.
- Step 1 scanner behavior is stubbed and currently returns an empty result set.
