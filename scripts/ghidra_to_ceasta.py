# -*- coding: utf-8 -*-
# the names, comments and prototypes you gave a program in Ghidra, for ceasta.
#
# in Ghidra: Window > Script Manager, add this folder to the script directories, run
# ghidra_to_ceasta.py; it asks where to save a .json.
# in ceasta: File > Import names (IDA, Ghidra, x64dbg)... and pick that .json.
#
# addresses are written as offsets from the image base, so it doesn't matter where each tool
# loaded the program (ghidra puts pie programs at 0x100000). jython and pyghidra both run it.
# @category ceasta

import json

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType

base = currentProgram.getImageBase()
out = {"format": "ceasta-names", "from": "ghidra", "names": [], "comments": [], "prototypes": []}

# names someone chose, or that came with the program's debug info
for sym in currentProgram.getSymbolTable().getAllSymbols(True):
    src = sym.getSource()
    a = sym.getAddress()
    if (src == SourceType.USER_DEFINED or src == SourceType.IMPORTED) and a.isMemoryAddress():
        out["names"].append({"rva": a.subtract(base), "name": sym.getName()})

# every kind of comment on an address, joined
listing = currentProgram.getListing()
kinds = (CodeUnit.EOL_COMMENT, CodeUnit.PRE_COMMENT, CodeUnit.PLATE_COMMENT, CodeUnit.REPEATABLE_COMMENT)
for a in listing.getCommentAddressIterator(currentProgram.getMemory(), True):
    parts = [listing.getComment(k, a) for k in kinds]
    parts = [p for p in parts if p]
    if parts:
        out["comments"].append({"rva": a.subtract(base), "text": " / ".join(parts)})

# prototypes that were set on purpose
for f in currentProgram.getFunctionManager().getFunctions(True):
    if f.getSignatureSource() == SourceType.USER_DEFINED:
        out["prototypes"].append({"rva": f.getEntryPoint().subtract(base),
                                  "prototype": f.getSignature().getPrototypeString()})

target = askFile("Save the names for ceasta", "Save")
f = open(target.getAbsolutePath(), "w")
f.write(json.dumps(out, indent=1))
f.close()
print("ceasta: wrote %d names, %d comments and %d prototypes to %s"
      % (len(out["names"]), len(out["comments"]), len(out["prototypes"]), target.getAbsolutePath()))
