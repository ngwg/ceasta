-- trace_calls.lua - a debugger plugin: log every call the program makes
--
-- run it while a process is stopped under the debugger (F9 to start). it single
-- steps and prints each call with its target's name. slow, but it shows control
-- flow through a small routine without setting breakpoints by hand.
--
-- this one only does something when a debug session is live, so it also shows the
-- ceasta.dbg.* side of the api and the "stop" event hook.

local MAX_STEPS = 4000

local function trace()
    local dbg = ceasta.dbg
    if dbg.state() ~= "stopped" then
        ceasta.warn("start debugging and stop the target first (F9)")
        return
    end
    local depth, steps, calls = 0, 0, 0
    while steps < MAX_STEPS do
        local pc = dbg.pc()
        local ins = ceasta.disasm(pc)
        if not ins then break end
        if ins.flow == "call" then
            local dst = ins.target and ceasta.location(ins.target) or "(indirect)"
            ceasta.log(("%s%s -> %s"):format(("  "):rep(math.min(depth, 8)), string.format("%X", pc), dst))
            calls = calls + 1
            depth = depth + 1
        elseif ins.flow == "ret" then
            depth = math.max(0, depth - 1)
        end
        local ok, err = dbg.step_into()
        if not ok then
            ceasta.warn("step failed: " .. tostring(err))
            break
        end
        -- the app pumps debug events between turns; the console runs synchronously,
        -- so give the state a moment to settle by re-reading pc on the next loop
        steps = steps + 1
        if dbg.state() ~= "stopped" then
            ceasta.log("target is no longer stopped, ending trace")
            break
        end
    end
    ceasta.log(("traced %d step(s), %d call(s)"):format(steps, calls))
end

ceasta.register_command("Trace calls (debugger)", trace,
    "single step the stopped target and log every call")

-- example event hook: announce each stop with the current location
ceasta.on("stop", function(pc)
    ceasta.log("debugger stopped at " .. ceasta.location(pc))
end)
