"""
Day 2 core deliverable: bounded symbolic execution from a function's
parameter (modeling attacker-controlled input, e.g. a CGI/request parameter)
to a dangerous sink call within that function.

Scope note (for the known-limitations section): this is INTRA-PROCEDURAL --
it explores within one function, treating its argument as symbolic, rather
than whole-program taint from a real network socket. That's the deliberate
scope cut for a 2-day budget; full taint from recv() to sink across the
whole call graph is future work (this matches the PRD's FR-3.4: bounded
exploration via budgets, not a promise of completeness).

Run with: python3 symbolic_trace.py <binary> <function_addr_hex> <sink_addr_hex> [sink_function_name]
"""
import sys
import json
import time
import logging
import angr
claripy = angr.claripy  # IMPORTANT: use angr's own bundled claripy, not a
                         # separately pip-installed one -- they produce
                         # incompatible symbolic-expression objects

logging.getLogger("angr").setLevel(logging.CRITICAL)

MAX_STEPS = 300          # hard step budget -- FR-3.4
MAX_WALLCLOCK_SEC = 60    # hard time budget -- FR-3.4


def run_trace(binary_path: str, func_addr: int, sink_addr: int) -> dict:
    proj = angr.Project(binary_path, auto_load_libs=False)

    # Model attacker-controlled input correctly: the ARGUMENT is a concrete
    # pointer (angr needs a real address to set up the calling convention),
    # but the MEMORY that pointer points to is symbolic -- that's what
    # actually represents "attacker controls this data". Passing a raw
    # symbolic value as the pointer itself (tried first) fails because angr
    # can't serialize an unconstrained address into a calling convention.
    BUF_ADDR = 0x40470000  # scratch address, arbitrary but fixed
    BUF_SIZE = 256          # bytes of symbolic attacker-controlled data
    prototype = "void x(char*)"
    state = proj.factory.call_state(func_addr, BUF_ADDR, prototype=prototype)
    sym_data = claripy.BVS("attacker_controlled_data", BUF_SIZE * 8)
    state.memory.store(BUF_ADDR, sym_data)

    simgr = proj.factory.simgr(state)

    start = time.time()
    steps_taken = 0
    found_state = None

    while steps_taken < MAX_STEPS and (time.time() - start) < MAX_WALLCLOCK_SEC:
        if not simgr.active:
            break
        simgr.step()
        steps_taken += 1
        for s in simgr.active:
            if s.addr == sink_addr:
                found_state = s
                break
        if found_state:
            break

    elapsed = round(time.time() - start, 2)

    result = {
        "binary": binary_path,
        "function_addr": hex(func_addr),
        "sink_addr": hex(sink_addr),
        "steps_taken": steps_taken,
        "elapsed_seconds": elapsed,
        "budget_exhausted": steps_taken >= MAX_STEPS or elapsed >= MAX_WALLCLOCK_SEC,
        "path_found": found_state is not None,
        "tainted_path": [],
        "crash_state": None,
    }

    if found_state is not None:
        result["tainted_path"] = [hex(a) for a in found_state.history.bbl_addrs] + [hex(found_state.addr)]
        try:
            result["crash_state"] = {
                "fault_address": hex(found_state.addr),
                "registers": {
                    "ip": str(found_state.regs.ip),
                    "sp": str(found_state.regs.sp),
                },
            }
        except Exception as e:
            result["crash_state"] = {"extraction_error": str(e)}

    return result


if __name__ == "__main__":
    binary_path = sys.argv[1]
    func_addr = int(sys.argv[2], 16)
    sink_addr = int(sys.argv[3], 16)
    sink_function = sys.argv[4] if len(sys.argv) > 4 else "unknown"

    result = run_trace(binary_path, func_addr, sink_addr)
    result["sink_function"] = sink_function
    result["note"] = ("intra-procedural: parameter treated as symbolic/attacker-controlled; "
                       "full network-to-sink taint across the whole call graph is descoped "
                       "for time, see known-limitations")
    print(json.dumps(result, indent=2))
