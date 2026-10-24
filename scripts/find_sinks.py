"""
Step 1 of Day 2: cheap pre-check. Load a binary, build its CFG, and report
which dangerous sinks it calls and from where. This tells us whether a
binary is even worth the expensive symbolic-exploration step.

Run with: python3 find_sinks.py <path-to-binary>
"""
import sys
import logging
import angr

logging.getLogger("angr").setLevel(logging.CRITICAL)

SINKS = ["strcpy", "system", "memcpy", "sprintf", "popen", "strcat", "exec", "execve"]

binary_path = sys.argv[1]
proj = angr.Project(binary_path, auto_load_libs=False)
print(f"[+] Loaded {binary_path} ({proj.arch.name})")

cfg = proj.analyses.CFGFast()
print(f"[+] CFG: {cfg.graph.number_of_nodes()} nodes, {len(cfg.kb.functions)} functions")

found_any = False
for sink_name in SINKS:
    sink_func = cfg.kb.functions.function(name=sink_name)
    if sink_func is None:
        continue
    sink_addr = sink_func.addr
    for caller_func in cfg.kb.functions.values():
        if caller_func.name == sink_name:
            continue
        for site in caller_func.get_call_sites():
            if caller_func.get_call_target(site) == sink_addr:
                print(f"    SINK: {caller_func.name} @ {hex(site)} -> {sink_name}")
                found_any = True

if not found_any:
    print("    (no direct calls to tracked sinks found)")
