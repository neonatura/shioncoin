
function send(a, v)
  userdata.txout = { }
  userdata.txout.addr = a
  userdata.txout.value = v
  userdata.total = userdata.total - v
end

function donate(farg)
  if (farg.value >= 1) then
    userdata.total = userdata.total + farg.value
    userdata.stamp = 0
    return farg.value
  end
  return 0
end

function spigot(farg)
  local a = abs(time() / 60)
  local b = abs(userdata.stamp / 60)
  if (a == b) then
    -- 1 SHC / minute --
    return 0
  end
  if (userdata.total >= 1) then
    send(farg.sender, 1)
    userdata.stamp = time()
    return 1
  end
  return 0
end

function init(farg)
  userdata.owner = farg.sender
  userdata.total = 0
  userdata.donate = donate
  userdata.spigot = spigot
  return 0
end

-- farg = { }
-- init(farg)
-- farg.sender = "test"
-- farg.value = 2
-- print(donate(farg))
-- print(spigot(farg))
-- 
-- print "userdata:"
-- for k, v in pairs(userdata) do
--   if (type(v) == "string" or type(v) == "number") then
--     print(k .. ": " .. v)
--   end
-- end

