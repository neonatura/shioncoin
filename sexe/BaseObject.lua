--
-- The "Base Object" class used to derive compatible SEXE classes on
-- the ShionCoin (SHC) virtual currency block-chain.
--

require 'math'
require 'io'
require 'crypt'

event ExecUpdateEvent

BaseObject = {}
BaseObject._VERSION = 3

param = { }

-- permissions
local PERM_ADMIN = "admin"

local function enablePerm(level)
	local vname = "map_" .. crypt.crc(level)
  if (BaseObject.data[vname] == nil) then
		BaseObject.data[vname] = { }
	end
end


function printvar(var)
	if (type(var) == "string") then
		println(var .. " [str]")
	elseif (type(var) == "number") then
		println (var .. " [num]")
	elseif (type(var) == "boolean") then
		println (var .. " [bool]")
	elseif (type(var) == "function") then
		println ("[func]")
	elseif (type(var) == "table") then
		println ("{")
		for k,v in pairs(var) do
			print(k .. "=")
			printvar(v)
		end
		println ("}")
	end
end

function BaseObject:New(template)
    -- The new instance of the BaseObject needs an index table.
    -- This next statement prefers to use "template" as the
    -- index table, but will fall back to self.
    -- Without the proper index table, your new BaseObject will
    -- not have the proper behavior.
    --
    template = template or self
    
    -- This call to setmetatable does 3 things:
    -- 1. Makes a new table.
    -- 2. Sets its metatable to the "index" table
    -- 3. Returns that table.
    --
    local newObject = setmetatable ({}, template)
    
    --
    -- Obtain the metatable of the newly instantiated table.
    -- Make sure that if the user attempts to access newObject[key]
    -- and newObject[key] is nil, that it will actually fall
    -- back to looking up template[key]...and so on, because template
    -- should also have a metatable with the correct __index metamethod.
    --
    local mt = getmetatable (newObject)
    mt.__index = template
    
    return newObject
end

function BaseObject:Subclass()
    --
    -- This is just a convenience function/semantic extension
    -- so that BaseObjects which need to inherit from a base BaseObject
    -- use a clearer function name to describe what they are doing.
    --
    return setmetatable({}, {__index = self})
end

function BaseObject.MultiSubclass(...)
    local parentClasses = {...}
    return setmetatable({}, 
    {
        __index = function(table, key)
            for _, parentClassTable in ipairs(parentClasses) do
                local value = parentClassTable[key]
                if value ~= nil then
                    return value
                end
            end
        end
    })
end

function BaseObject.getSentTime()
	return (param["timestamp"])
end

-- the address of the entity who initiated execution 
function BaseObject.getSentAddress()
	return (param["sender"])
end

function BaseObject.getUpdateTime()
	return (BaseObject.data["timestamp"])
end

-- the value sent by the entity who intiated execution
function BaseObject.getSentValue()
	local value = param["value"]
	return (value)
end

function BaseObject.getOwner()
	return (BaseObject.data["owner"])
end

function BaseObject.isOwner()
	if (BaseObject.getSentAddress() == BaseObject.getOwner()) then
		return (true)
	end
	return (false)
end

function BaseObject.getBlockHeight()
	return (param["height"])
end

-- the class's version
function BaseObject.getVersion()
	return BaseObject._VERSION
end

-- the name of the underlying script
function BaseObject.getClassName()
	return (param["class"])
end

-- callback to verify BaseObject is available.
function BaseObject.verify()
	if (BaseObject.getVersion() >= 3) then
		return (true)
	end
	return (false)
end

function BaseObject.incrFee(val)
	param["fee"] = math.max(0, param["fee"] + tonumber(val))
	if (param["fee"] > param["value"]) then
		BaseObject.setError("insufficient funds")
		return (false)
	end
	return (true)
end

function BaseObject.setFee(val)
	param["fee"] = math.max(0, tonumber(val))
	if (param["fee"] > param["value"]) then
		BaseObject.setError("insufficient funds")
		return (false)
	end
	return (true)
end

-- called when a data variable has changed
function BaseObject.update()
	if (BaseObject.data == nil) then
		-- not initialized
		return (false)
	end

	-- last updated time-stamp
	BaseObject.data["timestamp"] = param["timestamp"]
	BaseObject.data["height"] = param["height"]

	-- checksum for validation in block-chain
	local last_checksum = param["checksum"]
	param["checksum"] = crypt.sha2(BaseObject.data)
	if (last_checksum == param["checksum"]) then
		-- no changes have occurred.
		return (true)
	end

	-- tack on fee so that tx is stored on block-chain
	if (BaseObject.incrFee(0.0001) == false) then
		-- unable to afford fee
		return (false)
	end

	if (ExecUpdateEvent(param) == false) then
		-- unable to update userdata
		return (false)
	end

	-- persistently write any changed user-data variables
	io.serialize(param["iface"], BaseObject.data)
	return (true)
end

function BaseObject.setError(msg)
	BaseObject.setFee(0)
	param["error"] = msg
end

function BaseObject.isPerm(level)
	local vname = "map_" .. crypt.crc(level)
	local plist = BaseObject.data[vname]
	return (plist ~= nil)
end

function BaseObject.setPerm(level, addr, code)
	if (BaseObject.isOwner() == false) then
		return false
	end

	local vname = "map_" .. crypt.crc(level)
	local plist = BaseObject.data[vname]
	if (plist == nil) then
		return false
	end

	-- only ADMIN may set permissions
	local acc_vname = "map_" .. crypt.crc(PERM_ADMIN)
	if (plist[acc_vname] ~= true) then
		return false
	end

	if (code == nil) then code = true end
	plist[addr] = code
	return (BaseObject.update())
end

function BaseObject.unsetPerm(level, addr)
	if (BaseObject.isOwner() == false) then
		return false
	end

	local vname = "map_" .. crypt.crc(level)
	local plist = BaseObject.data[vname]
	if (plist == nil) then
		BaseObject.setError("invalid permission level")
		return false
	end

	-- only ADMIN may set permissions
	local acc_vname = "map_" .. crypt.crc(PERM_ADMIN)
	if (plist[acc_vname] ~= true) then
		return false
	end

	plist[addr] = nil
	return (BaseObject.update())
end

function BaseObject.isAdmin()
	if (BaseObject.isOwner() == true) then
		return (true)
	end
	return (BaseObject.hasPerm(PERM_ADMIN))
end

function BaseObject.hasPerm(level)
	local vname = "map_" .. crypt.crc(level)

	local plist = BaseObject.data[vname]
	if (plist == nil) then
		-- access level has no permission requirements
		return true
	end

	local sender = BaseObject.getSentAddress()
	if (plist[sender] == nil) then
		return false
	end

	return (plist[sender])
end

local function BaseObject_Initialize(arg, event_name)
	-- parameters
	param = arg

	if (arg["iface"] == nil) then
		return (false)
	end

	-- param
	param["iface"] = tostring(arg["iface"])
	param["sender"] = tostring(arg["sender"])
	param["class"] = tostring(arg["class"])
	param["timestamp"] = tonumber(arg["timestamp"])
	param["value"] = tonumber(arg["value"])
	param["height"] = tonumber(arg["height"])
	param["version"] = tonumber(arg["version"])

	if (param["version"] < BaseObject.getVersion()) then
		return (false)
	end

	-- runtime
	param["fee"] = 0.0
	param["checksum"] = ""

	BaseObject.data = io.unserialize(param["iface"])

	-- first time
	if (BaseObject.data == nil) then
		BaseObject.data = { }
		BaseObject.data["owner"] = tostring(arg["owner"])

		enablePerm(PERM_ADMIN)
	end

	return (true)
end
os.register("InitEvent", BaseObject_Initialize)
