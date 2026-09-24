-- hello.lua - the smallest useful plugin, a good starting point to copy from
-- it adds one command to the Plugins menu and prints a summary to the output log.

ceasta.register_command("Hello / file summary", function()
    local f = ceasta.file()
    ceasta.log(("%s  -  %s %s, %s"):format(f.name, f.format, f.arch, f.kind))
    ceasta.log(("  entry %s (%s)"):format(string.format("%X", f.entry), ceasta.name(f.entry)))
    ceasta.log(("  %d functions, %d imports, %d strings"):format(
        #ceasta.functions(), #ceasta.imports(), #ceasta.strings()))
end, "print a one line summary of the loaded file")
