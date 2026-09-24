-- find_crypto.lua - flag functions that look like crypto / hashing
--
-- heuristics, not proof: many rotates and xors, references to well known
-- constants, or an unusually high share of arithmetic. it renames strong hits
-- to crypto_* and leaves a comment so they stand out in the functions list.

-- constants that show up in common algorithms
local MARKERS = {
    [0x67452301] = "MD5/SHA1 init (A)",
    [0xefcdab89] = "MD5/SHA1 init (B)",
    [0x98badcfe] = "MD5/SHA1 init (C)",
    [0x10325476] = "MD5/SHA1 init (D)",
    [0x6a09e667] = "SHA-256 init",
    [0xbb67ae85] = "SHA-256 init",
    [0x9e3779b9] = "TEA/XXTEA delta",
    [0xedb88320] = "CRC32 (reflected)",
    [0x04c11db7] = "CRC32 poly",
    [0x5bd1e995] = "MurmurHash2",
    [0x1000193]  = "FNV prime",
    [0x811c9dc5] = "FNV offset",
    [0x8badf00d] = "watchdog magic",
}

local function scan()
    local hits = 0
    for _, fn in ipairs(ceasta.functions()) do
        if fn.thunk or fn.size == 0 then goto next end
        local a, stop = fn.addr, fn.addr + fn.size
        local rot, xor, arith, total = 0, 0, 0, 0
        local found = {}
        local guard = 0
        while a < stop and guard < 20000 do
            local ins = ceasta.disasm(a)
            if not ins then break end
            total = total + 1
            local m = ins.mnemonic
            if m == "rol" or m == "ror" or m == "shl" or m == "shr" or m == "shld" or m == "shrd" then
                rot = rot + 1
            elseif m == "xor" or m == "not" then
                xor = xor + 1
            elseif m == "add" or m == "sub" or m == "mul" or m == "and" or m == "or" or m == "imul" then
                arith = arith + 1
            end
            a = a + ins.size
            guard = guard + 1
        end
        if total == 0 then goto next end

        -- constant markers, read the whole function body once
        local body = ceasta.read(fn.addr, math.min(fn.size, 65536))
        for i = 1, #body - 3 do
            local b0, b1, b2, b3 = body:byte(i, i + 3)
            local v = b0 + b1 * 256 + b2 * 65536 + b3 * 16777216
            if MARKERS[v] then found[#found + 1] = MARKERS[v] end
        end

        local mixy = (rot + xor) / total
        if #found > 0 or (mixy > 0.12 and rot >= 3) then
            hits = hits + 1
            local why = #found > 0 and table.concat(found, ", ")
                or ("%d rotates, %d xors in %d insns"):format(rot, xor, total)
            ceasta.set_comment(fn.addr, "crypto? " .. why)
            local base = ceasta.name(fn.addr)
            if base:match("^sub_") then
                ceasta.set_name(fn.addr, "crypto_" .. string.format("%X", fn.addr))
            end
            ceasta.log(("%s  %s"):format(ceasta.location(fn.addr), why))
        end
        ::next::
    end
    ceasta.log(hits > 0 and ("crypto scan: %d candidate function(s)"):format(hits)
        or "crypto scan: nothing stood out")
end

ceasta.register_command("Find crypto / hashing", scan,
    "guess which functions do crypto and rename them crypto_*")
