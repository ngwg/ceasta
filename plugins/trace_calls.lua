-- trace_calls.lua - a debugger plugin: log every call the program makes
--
-- run it while a process is stopped under the debugger (F9 to start). it single
-- steps and prints each call with its target's name. slow, but it shows control
-- flow through a small routine without setting breakpoints by hand.
--
-- this one only does something when a debug session is live, so it also shows the
-- ceasta.dbg.* side of the api and the "stop" event hook.

local MAX_STEPS = 4000
local tracing = false

-- calls we don't follow: imports, indirect calls, and thunks that jump to an import
local function external(target)
    if not target or not ceasta.is_code(target) then return true end
    local first = ceasta.disasm(target)
    return first ~= nil and first.flow == "jump" and first.target == nil
end

local function trace()
    local dbg = ceasta.dbg
    if dbg.state() ~= "stopped" then
        ceasta.warn("start debugging and stop the target first (F9)")
        return
    end
    local depth, steps, calls = 0, 0, 0
    tracing = true
    while steps < MAX_STEPS do
        -- pc is a runtime address, the listing may sit elsewhere when aslr moved the image
        local pc = dbg.to_static(dbg.pc())
        local ins = pc and ceasta.disasm(pc)
        if not ins then
            ceasta.log("left the program's own code, ending trace")
            break
        end
        local step = dbg.step_into
        if ins.flow == "call" then
            local dst = ins.target and ceasta.location(ins.target) or "(indirect)"
            ceasta.log(("%s%s -> %s"):format(("  "):rep(math.min(depth, 8)), string.format("%X", pc), dst))
            calls = calls + 1
            if external(ins.target) then
                step = dbg.step_over -- imports and indirect calls run at full speed
            else
                depth = depth + 1
            end
        elseif ins.flow == "ret" then
            depth = math.max(0, depth - 1)
        end
        -- steps wait until the target stops again (or exits)
        local ok, err = step()
        steps = steps + 1
        if not ok then
            ceasta.log(err and ("step failed: " .. tostring(err)) or "target is no longer stopped, ending trace")
            break
        end
    end
    tracing = false
    ceasta.log(("traced %d step(s), %d call(s)"):format(steps, calls))
end

ceasta.register_command("Trace calls (debugger)", trace,
    "single step the stopped target and log every call")

-- example event hook: announce each stop with the current location
ceasta.on("stop", function(pc)
    if not tracing then
        ceasta.log("debugger stopped at " .. ceasta.location(pc))
    end
end)
