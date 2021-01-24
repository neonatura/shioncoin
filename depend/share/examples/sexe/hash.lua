-- standard checksum algorythms

require 'crypt'

local val = arg[1]

if (val == nil) then
  print("usage: hash.sx <text>")
  return
end

local crc = crypt.crc(val)

println("VALUE: " .. val)
println("CHECKSUM: " .. crc)

