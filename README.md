# FirmwareX — IoTGoat Firmware Security Analysis Pipeline

## Project Overview

FirmwareX is a firmware security analysis prototype that examines IoTGoat firmware binaries for security-hardening weaknesses and potential hardcoded secrets. It normalizes findings into the project's Appendix-A finding schema and generates a static HTML report.

### Analysis Components

- **Binary hardening audit:** Examines ELF binary security properties, including NX, PIE, RELRO, stack canaries, and stripped status.
- **Secret scanning:** Detects patterns that may indicate hardcoded secrets. Heuristic matches require manual validation.
- **Symbolic analysis:** Demonstrates an intra-procedural symbolic path to a sink in the `uhttpd` binary.
- **Finding normalization:** Combines hardening, secret-scanning, and symbolic-analysis results into a consistent JSON schema.
- **HTML reporting:** Generates a static report containing findings and a sample of the binary hardening matrix.

## Project Structure

```text
firmwarex-internship/
├── reports/
│   ├── hardening_matrix.json
│   ├── normalized_findings.json
│   ├── report.html
│   ├── secrets.json
│   └── symbolic_finding.json
├── scripts/
│   ├── find_sinks.py
│   ├── hardening_audit.py
│   ├── normalize_and_report.py
│   ├── secret_scanner.py
│   └── symbolic_trace.py
├── requirements.txt
└── README.md
```

## Environment and Dependencies

The Python dependencies listed in `requirements.txt` include:

- `angr`
- `pyelftools`

Activate the project's virtual environment in Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install the Python dependencies:

```powershell
python -m pip install -r requirements.txt
```

Binwalk is a separate system dependency and is not installed through the project's Python requirements. Install and configure it using instructions appropriate to your operating system.

## Running the Analysis Pipeline

Run commands from the project root:

```powershell
python .\scripts\hardening_audit.py <ROOTFS_PATH> > .\reports\hardening_matrix.json
python .\scripts\secret_scanner.py <ROOTFS_PATH> > .\reports\secrets.json
```

Replace `<ROOTFS_PATH>` with the actual path to the extracted firmware filesystem.

Identify a suitable target function and sink in the `uhttpd` binary:

```powershell
python .\scripts\find_sinks.py <UHTTPD_BINARY_PATH>
```

Use the function and sink addresses reported by the tool:

```powershell
python .\scripts\symbolic_trace.py <UHTTPD_BINARY_PATH> <FUNCTION_ADDRESS> <SINK_ADDRESS> > .\reports\symbolic_finding.json
```

Generate the normalized findings and HTML report:

```powershell
python .\scripts\normalize_and_report.py
```

Open the report:

```powershell
Start-Process (Resolve-Path .\reports\report.html).Path
```

**Important:** The commands above assume that the input firmware filesystem and target binary have already been extracted and that the paths and addresses have been verified. Replace the placeholders with actual values. The original extraction instructions use Linux-specific tooling and are not directly executable in Windows PowerShell.

## Current Results

The current generated outputs contain:

- **176** binary records in `hardening_matrix.json`
- **21** secret-scanner detections in `secrets.json`
- **201** normalized findings in `normalized_findings.json`
- **1 high**, **113 medium**, and **87 low** risk-rated normalized findings
- A static HTML report at `reports/report.html`

These counts describe the current generated files and may change when the input data or analysis logic changes.

Risk ratings and confidence labels are tool-generated triage information. They do not establish that every detection is a confirmed vulnerability.

## Known Limitations

- **Intra-procedural symbolic analysis:** The prototype examines a path within a function rather than tracing attacker-controlled input from a network socket across the complete call graph. Whole-program taint analysis is future work.
- **No full-system QEMU emulation:** Dynamic full-system firmware execution was not implemented.
- **No fuzzing:** Fuzz testing was outside the implemented scope.
- **Static HTML report only:** The project generates a standalone HTML report rather than a live API, database, or interactive dashboard.
- **One symbolic-analysis target:** The symbolic trace was performed on `uhttpd` as a proof of technique, rather than on every binary. The hardening and secret-scanning components produced the broader inventory.
- **Heuristic secret detections:** Pattern and entropy matches may be benign or test-fixture data and need manual verification.
- **Hardening interpretation:** Security properties reported for kernel modules and other nonstandard ELF objects may need context-specific interpretation before being treated as vulnerabilities.

## Development Challenges and Lessons

1. **Binwalk installation:** The PyPI package named `binwalk` may not provide the intended firmware extraction tool. Use the appropriate system package or official installation instructions.
2. **Extraction permissions:** Firmware extraction may require appropriate permissions and extraction options.
3. **Special filesystem entries:** Traversing device files, FIFOs, or virtual filesystem paths can cause hangs. Filesystem traversal should handle or exclude these entries safely.
4. **ELF segment identification:** The hardening audit must interpret ELF segment types correctly when checking properties such as GNU stack and GNU RELRO.
5. **angr and claripy compatibility:** Mixing incompatible symbolic-expression implementations can cause errors. Use compatible versions of the libraries provided by the installed angr environment.
6. **Symbolic pointers:** Symbolic values used as pointers require appropriate memory modelling; concrete addresses with symbolic memory contents may be necessary for the intended analysis.

## Submission Evidence Checklist

- [ ] Screen recording demonstrating the analysis pipeline and generated report
- [x] `reports/hardening_matrix.json` — 176 binary records
- [x] `reports/secrets.json` — 21 detections
- [x] `reports/symbolic_finding.json` — generated symbolic-analysis result
- [x] `reports/normalized_findings.json` — 201 normalized findings
- [x] `reports/report.html` — generated static HTML report
- [x] `README.md` — project documentation

*The checked items indicate that the files were present and validated during development. They do not independently verify every security finding or establish that the screen recording has been completed.*
