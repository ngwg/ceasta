-- name_wrappers.lua - name tiny functions after the api they wrap
--
-- a lot of sub_xxxx are one line wrappers: set up args, jump/call one import,
-- return. naming them w_<import> makes call sites readable without any real work.

local function only_call_target(fn)
    -- returns the single call/jump target of a short function, or nil
    local a, stop = fn.addr, fn.addr + fn.size
    local target, calls, guard = nil, 0, 0
    while a < stop and guard < 64 do
        local ins = ceasta.disasm(a)
        if not ins then return nil end
        if ins.flow == "call" or ins.flow == "jump" then
            if ins.target then
                calls = calls + 1
                target = ins.target
            else
                return nil -- indirect, can't tell
            end
        end
        a = a + ins.size
        guard = guard + 1
    end
    if calls == 1 then return target end
    return nil
end

local function run()
    -- map every import slot and thunk to a readable name up front
    local named = 0
    for _, fn in ipairs(ceasta.functions()) do
        if fn.size == 0 or fn.size > 48 then goto next end
        if not ceasta.name(fn.addr):match("^sub_") then goto next end
        local t = only_call_target(fn)
        if not t then goto next end
        local callee = ceasta.name(t)
        if callee == "" or callee:match("^sub_") or callee:match("^loc_") then goto next end
        callee = callee:gsub("^j_", "")
        if ceasta.set_name(fn.addr, "w_" .. callee) then
            ceasta.set_comment(fn.addr, "wrapper for " .. callee)
            named = named + 1
        end
        ::next::
    end
    ceasta.log(("named %d wrapper function(s)"):format(named))
end

ceasta.register_command("Name API wrappers", run,
    "rename one-call wrapper functions to w_<callee>")
