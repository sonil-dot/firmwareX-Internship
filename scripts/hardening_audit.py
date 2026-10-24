"""
FirmwareX — Static Hardening Audit
Satisfies FR-1.3 (enumerate ELFs, arch/endianness/bitness) and
FR-1.4 (NX, PIE, RELRO, stack canary, FORTIFY, stripped).

Run with: python3 hardening_audit.py <rootfs_dir> > hardening_matrix.json
"""

import os
import sys
import json
from elftools.elf.elffile import ELFFile


SKIP_DIRS = {"dev", "proc", "sys"}  # special filesystems: device nodes, FIFOs
                                     # that can hang forever on open()


def is_elf(path: str) -> bool:
    try:
        # os.stat first so we only ever open() a plain regular file
        st = os.stat(path, follow_symlinks=False)
        if not os.path.isfile(path) or os.path.islink(path):
            return False
        import stat as statmod
        if not statmod.S_ISREG(st.st_mode):
            return False
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except (OSError, PermissionError):
        return False


def find_elfs(rootfs: str):
    elfs = []
    for dirpath, dirnames, filenames in os.walk(rootfs):
        # prune special-filesystem directories in place so os.walk skips them
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            if is_elf(full):
                elfs.append(full)
    return elfs


def audit_one(path: str) -> dict:
    result = {
        "path": path,
        "architecture": None, "endianness": None, "bits": None,
        "elf_type": None,
        "nx": False, "pie": False, "relro": "none",
        "stack_canary": False, "fortify": False, "stripped": True,
        "error": None,
    }
    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)

            result["architecture"] = elf.get_machine_arch()
            result["endianness"] = "little" if elf.little_endian else "big"
            result["bits"] = 64 if elf.elfclass == 64 else 32
            result["elf_type"] = elf.header["e_type"]  # ET_EXEC / ET_DYN
            # PIE heuristic: ET_DYN *with* an entry point and an INTERP segment
            # (plain shared libs are ET_DYN too, but don't count as PIE)
            has_interp = any(
                seg["p_type"] == "PT_INTERP" for seg in elf.iter_segments()
            )
            result["pie"] = (elf.header["e_type"] == "ET_DYN") and has_interp

            # NX: look for the GNU_STACK program header; if absent, assume
            # executable stack (the historical default)
            gnu_stack = None
            for seg in elf.iter_segments():
                if seg["p_type"] == "PT_GNU_STACK":
                    gnu_stack = seg
                    break
            if gnu_stack is not None:
                result["nx"] = not bool(gnu_stack["p_flags"] & 0x1)  # PF_X = 1
            else:
                result["nx"] = False

            # RELRO: GNU_RELRO segment present = partial; also BIND_NOW = full
            has_relro_seg = any(
                seg["p_type"] == "PT_GNU_RELRO" for seg in elf.iter_segments()
            )
            bind_now = False
            dynamic = elf.get_section_by_name(".dynamic")
            if dynamic is not None:
                for tag in dynamic.iter_tags():
                    if tag.entry.d_tag == "DT_BIND_NOW":
                        bind_now = True
                    if tag.entry.d_tag == "DT_FLAGS" and tag.entry.d_val & 0x8:  # DF_BIND_NOW
                        bind_now = True
                    if tag.entry.d_tag == "DT_FLAGS_1" and tag.entry.d_val & 0x1:  # DF_1_NOW
                        bind_now = True
            if has_relro_seg and bind_now:
                result["relro"] = "full"
            elif has_relro_seg:
                result["relro"] = "partial"
            else:
                result["relro"] = "none"

            # stack canary + FORTIFY: look at the dynamic symbol table
            dynsym = elf.get_section_by_name(".dynsym")
            symtab = elf.get_section_by_name(".symtab")
            result["stripped"] = symtab is None

            symbol_names = set()
            for sec in (dynsym, symtab):
                if sec is None:
                    continue
                for sym in sec.iter_symbols():
                    symbol_names.add(sym.name)

            result["stack_canary"] = "__stack_chk_fail" in symbol_names
            result["fortify"] = any(s.endswith("_chk") and s != "__stack_chk_fail"
                                     for s in symbol_names)

    except Exception as e:
        result["error"] = str(e)

    return result


if __name__ == "__main__":
    rootfs = sys.argv[1] if len(sys.argv) > 1 else "."
    elfs = find_elfs(rootfs)
    print(f"[+] Found {len(elfs)} ELF files under {rootfs}", file=sys.stderr)

    matrix = [audit_one(p) for p in elfs]
    ok = [m for m in matrix if m["error"] is None]
    print(f"[+] Successfully audited {len(ok)}/{len(matrix)}", file=sys.stderr)

    print(json.dumps(matrix, indent=2))
