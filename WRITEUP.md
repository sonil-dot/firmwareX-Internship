# FirmwareX — Final Write-up

## What was built

An automated IoT firmware vulnerability analysis pipeline, run end to end
against OWASP IoTGoat (a real, publicly available router firmware image).
The pipeline:

1. Unpacks a raw firmware image (binwalk) into a full root filesystem
2. Statically audits every extracted ELF binary for missing exploit
   mitigations (NX, PIE, RELRO, stack canary, FORTIFY, stripped)
3. Scans the filesystem for hardcoded secrets and high-entropy tokens,
   with confidence calibration and automatic redaction (only a SHA-256
   fingerprint is ever stored, never the raw secret)
4. Runs bounded, function-level symbolic execution (angr) to trace a
   path from a function's attacker-controlled parameter to a dangerous
   sink call (strcpy/sprintf/memcpy/system/etc.)
5. Normalizes every finding from all three stages into one CWE-classified
   schema and renders a static HTML report

## Results (real run against IoTGoat-raspberry-pi2)

| Metric | Result |
|---|---|
| Firmware unpacked | 1,011 files extracted from a real SquashFS image |
| Binaries hardening-audited | 176 / 176 (100%) |
| Missing stack canary | 176 / 176 |
| No RELRO | 87 / 176 |
| Executable stack (no NX) | 89 / 176 |
| Secret/crypto findings | 24 (confidence-calibrated, noise-filtered from an initial 102) |
| Symbolic taint-to-sink findings | 1 verified path in `uhttpd` reaching a `sprintf` call (CWE-134) |
| Total normalized findings | 201 |

## Design decisions & trade-offs

**NetworkX instead of Neo4j.** Not needed for this project's actual
pipeline (firmware analysis doesn't require attack-path graphing — that
was the companion red-team project's concern), but the same reasoning
applies elsewhere in this codebase: favor in-process, zero-infrastructure
tools over a database server when the data fits in memory, so the whole
pipeline runs with `python3 script.py`, nothing to stand up or tear down.

**Intra-procedural symbolic execution, not whole-binary.** Full taint
tracing from a real network `recv()` call through `uhttpd`'s entire
364-function call graph risks severe path explosion and was not
tractable in the available time. Instead, each target function's
parameter is modeled as symbolic/attacker-controlled directly, and
exploration is bounded (300 steps / 60 seconds). This is a real,
verifiable technique — not a toy example — but it is a narrower claim
than full network-to-sink taint analysis. The finding should be read as
"this function reaches this sink under attacker-controlled input,"
not "this is remotely exploitable over the network without further
analysis."

**No QEMU full-system emulation, no fuzzing, no dashboard/API.** All
three are listed as "Should", not "Must", in the PRD's MoSCoW
prioritization. Static analysis, secret scanning, and symbolic execution
cover the "Must" requirements end to end; the cut capabilities would
have required most of a second week to build and validate safely
(especially network-service emulation and containment).

**Confidence calibration over raw counts.** The secret scanner's first
pass produced 102 findings; 78 of those were high-entropy hits inside
compiled binary code, which is not a meaningful signal (machine code is
naturally high-entropy). Filtering those down to 24 calibrated findings,
and explicitly downgrading confidence on crypto-library self-test
fixtures (e.g. `libmbedcrypto.so`'s embedded test certificates), was a
deliberate choice to keep the report trustworthy rather than inflating
the finding count.

## Known limitations

- Symbolic execution is intra-procedural (see above), covering one
  binary (`uhttpd`) as a proof of technique, not all 176.
- No full-system QEMU emulation — network services are not actually
  brought up and exercised dynamically.
- No fuzzing (AFL++) — depends on the emulation layer above.
- No REST API or interactive dashboard — results are served as one
  static HTML report instead of a FastAPI + Postgres + dashboard stack.
- The private-key findings in `libmbedcrypto.so` are very likely the
  library's own embedded self-test certificates, not real device
  secrets — flagged at `heuristic` confidence rather than presented as
  confirmed findings, and would need manual review to resolve either way.

## Debugging notes (real issues hit and fixed, not hypothetical)

1. `pip install binwalk` installs an unrelated, broken package — the
   real tool is `apt-get install binwalk`.
2. binwalk refuses to extract firmware as root without `--run-as=root`.
3. Walking into `/dev` during filesystem traversal can hang forever on
   special files (FIFOs/device nodes); excluded `dev/proc/sys` explicitly.
4. pyelftools' segment type strings are `PT_GNU_STACK` / `PT_GNU_RELRO`,
   not `GNU_STACK` / `GNU_RELRO` — caught by validating against a known
   ground-truth binary (compiled with explicit, known hardening flags)
   before trusting results on real firmware.
5. angr bundles its own internal `claripy` (`angr.claripy`); importing
   the separately pip-installed `claripy` package produces incompatible
   symbolic-expression objects and fails with a confusing memory-store
   error.
6. A raw symbolic value cannot be passed directly as a pointer argument
   to `call_state` — the argument must be a concrete address, with the
   memory it points to marked symbolic instead.
7. The first version of the symbolic-execution script's output schema
   was missing `sink_function` and `note` fields that the downstream
   normalizer expected — caught when running the pipeline fresh on a
   second machine, fixed at the source rather than patched around.

## Conclusion

The core "Must" requirements of the PRD are met with real, independently
reproduced results (identical output was obtained running the full
pipeline on two separate machines). The cut scope (full-system emulation,
fuzzing, dashboard/API) was deliberate and is documented rather than
silently dropped, consistent with the PRD's own framing of full-system
emulation as "an open research problem" the engine should handle
best-effort rather than promise completeness on.
