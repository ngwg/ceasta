# -*- coding: utf-8 -*-
# the names, comments and prototypes you gave a program in IDA, for ceasta.
#
# in IDA: File > Script file... and pick this file; it asks where to save a .json.
# in ceasta: File > Import names (IDA, Ghidra, x64dbg)... and pick that .json.
#
# addresses are written as offsets from the image base, so it doesn't matter where each tool
# loaded the program. IDA 7.4 and newer (python 3).

import json

import ida_bytes
import ida_kernwin
import ida_nalt
import idautils
import idc

base = ida_nalt.get_imagebase()
out = {"format": "ceasta-names", "from": "ida", "names": [], "comments": [], "prototypes": []}

# the names someone chose (not sub_401000 and friends)
for ea, name in idautils.Names():
    if ida_bytes.has_user_name(ida_bytes.get_flags(ea)):
        out["names"].append({"rva": ea - base, "name": name})

# comments, regular and repeatable
for seg in idautils.Segments():
    for ea in idautils.Heads(seg, idc.get_segm_end(seg)):
        text = idc.get_cmt(ea, 0) or idc.get_cmt(ea, 1)
        if text:
            out["comments"].append({"rva": ea - base, "text": text})

# prototypes that were set on purpose: IDA prints them without the name, "int __cdecl(int a1)"
for ea in idautils.Functions():
    t = idc.get_type(ea)
    if t and "(" in t and (idc.get_func_flags(ea) & idc.FUNC_LIB) == 0:  # not a library function
        name = idc.get_func_name(ea)
        out["prototypes"].append({"rva": ea - base, "prototype": t.replace("(", " " + name + "(", 1)})

path = ida_kernwin.ask_file(1, "*.json", "Save the names for ceasta")
if path:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)
    print("ceasta: wrote %d names, %d comments and %d prototypes to %s"
          % (len(out["names"]), len(out["comments"]), len(out["prototypes"]), path))
