-- strings_report.lua - group interesting strings and jump to them
--
-- buckets the analysed strings (urls, paths, registry keys, format strings, ...)
-- and, when run, prints the interesting ones with the function that uses each.
-- also registers "goto next interesting string" to walk them one at a time.

local PATTERNS = {
    { "url",      "^%a[%w+.-]*://" },
    { "unc path", "^\\\\" },
    { "path",     "[A-Za-z]:\\" },
    { "path",     "^/%a+/" },
    { "registry", "^[Ss][Oo][Ff][Tt][Ww][Aa][Rr][Ee]\\" },
    { "registry", "^HKEY_" },
    { "format",   "%%[-+ #0]?%d*%.?%d*[diouxXeEfgGscp]" },
    { "command",  "cmd%.exe" },
    { "command",  "/bin/sh" },
    { "crypto",   "[Aa][Ee][Ss]" },
    { "network",  "[Hh][Tt][Tt][Pp]" },
    { "error",    "[Ee]rror" },
}

local function classify(text)
    for _, p in ipairs(PATTERNS) do
        if text:find(p[2]) then return p[1] end
    end
    return nil
end

local interesting = {}

local function build()
    interesting = {}
    local by_kind = {}
    for _, s in ipairs(ceasta.strings()) do
        local kind = classify(s.text)
        if kind then
            interesting[#interesting + 1] = s.addr
            by_kind[kind] = (by_kind[kind] or 0) + 1
        end
    end
    return by_kind
end

ceasta.register_command("Strings report", function()
    local by_kind = build()
    if #interesting == 0 then
        ceasta.log("no interesting strings found")
        return
    end
    local kinds = {}
    for k in pairs(by_kind) do kinds[#kinds + 1] = k end
    table.sort(kinds)
    for _, k in ipairs(kinds) do
        ceasta.log(("%-9s %d"):format(k, by_kind[k]))
    end
    ceasta.log("---")
    for _, addr in ipairs(interesting) do
        local xr = ceasta.xrefs_to(addr)
        local used = #xr > 0 and (" <- " .. ceasta.location(xr[1].from)) or ""
        ceasta.log(("%s  %s%s"):format(string.format("%X", addr), ceasta.read_cstr(addr, 60), used))
    end
    ceasta.log(("%d interesting string(s)"):format(#interesting))
end, "list urls, paths, registry keys and format strings")

local cursor = 0
ceasta.register_command("Go to next interesting string", function()
    if #interesting == 0 then build() end
    if #interesting == 0 then
        ceasta.warn("no interesting strings")
        return
    end
    cursor = cursor % #interesting + 1
    ceasta.goto_addr(interesting[cursor])
end, "jump to the next url / path / format string")
