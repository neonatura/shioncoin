-- Some simple time examples supported by SEXE compiled bytecode.

require 'time'

local t = time.time()
println("Local Time: " .. time.ctime(t))

-- unix epoch time
println("Unix Timestamp: " .. time.utime(t))

-- time math example
local ONE_YEAR = 31536000
local ta = t + ONE_YEAR
println("Future Time: " .. time.strftime(ta, "%x %T"))

-- compatible with unix time-stamp conversion
local result = "FAIL"
if (time.utime(t) == time.utime(time.timeu(time.utime(t)))) then
  result = "OK"
end
println ("Self-check: " .. result)
