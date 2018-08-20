-- BaseContext: manage contextual information 
-- require 'BaseObject'

require 'string'
event ContextCreateEvent

BaseContext = BaseObject:Subclass();

-- two years
local MAX_CONTEXT_PERIOD = 63072000

-- permission to create context
local PERM_CONTEXT = "context"

function BaseContext.getContextId(label)
	return (label)
end

function BaseContext.setContext(label, value)
	-- check perm
	if (BaseContext.hasPerm(PERM_CONTEXT) == false) then
		BaseContext.setError("permission denied")
		return (false)
	end

	local arg = { }
	arg["label"] = BaseContext.getContextId(label)
	arg["value"] = value
	if (ContextCreateEvent(arg) == false) then
		BaseContext.setError("error creating context")
		return (false)
	end

	return (BaseContext.update())
end

function BaseContext.setContextAt(label, value, lat, lon, stamp)
	if (stamp == nil) then stamp = 0 end
	if (stamp == 0) then stamp = BaseContext.getSentTime() end
	lat = math.floor(tonumber(lat), 2)
	lon = math.floor(tonumber(lon), 2)

	local ctx_id = BaseContext.getContextId(label)
	if (BaseContext.data.Context.ref[ctx_id] ~= nil) then
		BaseContext.setError("context already registered")
		return (false)
	end

	-- create a context on the block-chain with the information
	if (BaseContext.setContext(label, value) == false) then
		return (false)
	end

	ref = { }
	ref["timestamp"] = stamp
	ref["latitude"] = lat
	ref["longitude"] = lon
	BaseContext.data.Context.ref[ctx_id] = ref

	return (BaseContext.update())
end

function BaseContext.getContext(label)
	return (shc_context_get(BaseContext.getContextId(label)))
end

-- obtain list of events at location within max time
function BaseContext.getContextAt(lat, lon, min_time, max_time)
	local now = BaseContext.getSentTime()
	lat = math.floor(lat, 2)
	lon = math.floor(lon, 2)
	if (min_time == nil) then min_time = 0 end
	if (max_time == nil) then max_time = 0 end

	/* limit to four year window */
	min_time = math.max(min_time, BaseContext.getSentTime() - MAX_CONTEXT_PERIOD); 
	if (max_time < now) then max_time = now + MAX_CONTEXT_PERIOD end

	local ret = { }
	for k,v in pairs(BaseContext.data.Context.ref) do
		if (v.latitude == lat and v.longitude == lon) then
			if (v.timestamp >= min_time and v.timestamp <= max_time) then
				ret[k] = v
			end
		end
	end

	return (ret)
end

-- remove entries older than 2 years 
function BaseContext.pruneContext()
	if (BaseContext.isAdmin() == false) then
		BaseContext.setError("permission denied")
		return (false)
	end

	local ref = { }
	local min_time = BaseContext.getSentTime() - MAX_CONTEXT_PERIOD
	for k,v in pairs(BaseContext.data.Context.ref) do
		if (v.timestamp >= min_time) then
			ref[k] = v
		end
	end
	BaseContext.data.Context.ref = ref

	return (BaseContext.update())
end

local function BaseContext_Initialize(arg, event_name)
	if (BaseContext.data == nil) then 
		return (false)
	end
	if (BaseContext.data.Context == nil) then
		BaseContext.data.Context = { }
		BaseContext.data.Context.ref = { }
	end
	return (true)
end
os.register("InitEvent", BaseContext_Initialize)
