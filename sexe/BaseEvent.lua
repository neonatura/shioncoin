-- BaseEvent: manage Event accomodations
-- require 'BaseContext'

require 'crypt'

BaseEvent = BaseContext:Subclass();

local MIN_REGISTER_VALUE = 18
local DEFAULT_REGISTER_VALUE = 100
local MIN_REGISTER_PERIOD = 1000
-- one year maximum
local MAX_REGISTER_PERIOD = 63072000
-- serial number of ticket
local TICKET_SEED_MASK = 1000000000

local function enablePerm(level)
	local vname = "map_" .. crypt.crc(level)
	if (BaseObject.data[vname] == nil) then
		BaseObject.data[vname] = { }
	end
end

function BaseContext.createEventId(data)
	return ("event:" .. crypt.sha2(data))
end

function BaseContext.createTicketId(eve_id)
	local seed = BaseEvent.data.Event.config["ticketSeed"]
	local t_id = crypt.crc(eve_id)
	BaseEvent.data.Event.config["ticketSeed"] = math.mod(seed + t_id, TICKET_SEED_MASK)
	return ("ticket:" .. BaseEvent.data.Event.config["ticketSeed"])
end

function BaseEvent.getRegisterValue()
	local value = BaseEvent.data.Event.config["registerValue"]
	value = math.max(value, MIN_REGISTER_VALUE)
	return (value)
end

function BaseEvent.setRegisterValue(value)
	if (BaseEvent.isAdmin() == false) then
		BaseEvent.setError("permission denied")
		return (false)
	end

	if (value == nil or value < MIN_REGISTER_VALUE) then
		BaseEvent.setError("invalid value specified")
		return (false)
	end

	BaseEvent.data.Event.config["registerValue"] = value
	return (BaseEvent.update())
end

function BaseEvent.newEvent(desc, stamp, fee, max_occ)
	local val = BaseEvent.getSentValue();
	if (val < BaseEvent.getRegisterValue()) then
		BaseEvent.setError("insuffient funds")
		return (nil)
	end

	local source = BaseEvent.getSentAddress()
	local place = BaseEvent.data.Event.register[source]
	if (place == nil) then
		BaseEvent.setError("location not recognized")
		return (nil)
	end

	if (stamp == nil or stamp < BaseEvent.getSentTime()) then
		BaseEvent.setError("invalid timestamp specified");
		return (nil)
	end

	if (max_occ < 1) then
		BaseEvent.setError("invalid maximum occupancy")
		return (nil)
	end

	-- create Event
	Event = { }
	Event.latitude = place.latitude
	Event.longitude = place.longitude
	Event.name = place.label
	Event.desc = desc
	Event.registered = BaseEvent.getSentTime()
	Event.stamp = stamp
	Event.fee = fee
	Event.occupancy = max_occ

	local eve_id = BaseEvent.createEventId(Event)
	if (BaseEvent.setContextAt(eve_id, Event, stamp, place.latitude, place.longitude) == false) then
		-- insufficient funds to create context
		BaseEvent.setError("error creating context")
		return (nil)
	end

	BaseEvent.data.Event.ticket[eve_id] = { }

	-- persist
	if (BaseEvent.update() == false) then
		return (nil)
	end

	Event.eventid = eve_id
	return (Event)
end

function BaseEvent.purchaseEvent(eve_id)
	if (BaseEvent.data.Event.ticket[eve_id] == nil) then
		BaseEvent.setError("unknown event specified")
		return (nil)
	end

	local Event = BaseEvent.getEvent(eve_id)
	if (Event == nil) then
		BaseEvent.setError("error loading event")
		return (nil)
	end

	if (Event.stamp < BaseEvent.getSentTime()) then
		BaseEvent.setError("event not available");
		return (nil)
	end

	local fee = Event.fee
	if (fee == nil or fee <= 0.0001 or value < fee) then
		BaseEvent.setError("insufficient funds")
		return (nil)
	end

	if (BaseEvent.getTicketTotal(eve_id) >= Event.occupancy) then
		BaseEvent.setError("ticket limit reached")
		return (nil)
	end

	-- create ticket
	local sender = BaseEvent.getSentAddress()
	local t_id = BaseEvent.createTicketId(eve_id)
	BaseEvent.data.Event.ticket[eve_id][t_id] = sender
	if (BaseEvent.update() == false) then
		return (nil)
	end

	Event.ticket = t_id
	return (Event)
end

function BaseEvent.getTicketOf(addr, eve_id)
	if (BaseEvent.data.Event.ticket[eve_id] == nil) then
		BaseEvent.setError("unknown event")
		return (nil)
	end

	local ret = { }
	if (BaseEvent.data.Event.ticket[eve_id][addr] ~= nil) then
		for k,v in pairs(BaseEvent.data.Event.ticket[eve_id]) do
			if (addr == v) then
				ret[k] = v
			end
		end
	end

	return (ret)
end

function BaseEvent.getTicket(eve_id)
	return (BaseEvent.getTicketOf(BaseEvent.getSentAddress()))
end

function BaseEvent.getTicketTotal(eve_id)
	local ret = 0

	if (BaseEvent.data.Event.ticket[eve_id] ~= nil) then
		for k,v in pairs(BaseEvent.data.Event.ticket[eve_id]) do
			ret = ret + 1
		end
	end

	return (ret)
end

-- assign a physical location for use
function BaseEvent.registerPlace(source, lat, lon, label)
	if (BaseEvent.isAdmin() == false) then
		BaseEvent.setError("permission denied")
		return (false)
	end

	if (label == nil) then label = "" end
	if (string.len(label) > 256) then
		BaseEvent.setError("location name exceeds 256 characters")
		return (false)
	end

	if (BaseEvent.setPerm(PERM_CONTEXT, source, true) == false) then
		BaseEvent.setError("permission denied")
		return (false)
	end

	loc = { }
	loc.latitude = math.floor(lat, 2)
	loc.longitude = math.floor(lon, 2)
	loc.label = label

	BaseEvent.data.Event.register[source] = loc
	return (BaseEvent.update());
end

function BaseEvent.unregisterPlace()
	local source = BaseEvent.getSentAddress()
	BaseEvent.data.Event.register[source] = nil
	return (BaseEvent.update());
end

function BaseEvent.getRegister()
	return (BaseEvent.data.Event.register)
end

function BaseEvent.getEvent(eve_id)
	return (BaseEvent.getContext(eve_id))
end

-- obtain list of events at location for duration specified
function BaseEvent.getEventAt(lat, lon, max_time)
	return BaseEvent.getContextAt(lat, lon, max_time)
end

local function BaseEvent_Initialize(arg, event_name)
	if (BaseEvent.data == nil) then
		return (false)
	end

	-- first time
	if (BaseEvent.data.Event == nil) then
		BaseEvent.data.Event = { }
		BaseEvent.data.Event.config = { }
		BaseEvent.data.Event.config["registerValue"] = DEFAULT_REGISTER_VALUE
		BaseEvent.data.Event.config["ticketSeed"] = 1
		BaseEvent.data.Event.ticket = { }
		BaseEvent.data.Event.register = { }

		-- require permission to create new events
		enablePerm(PERM_CONTEXT)
	  BaseEvent.setPerm(PERM_CONTEXT, BaseObject.data["owner"], true)
	end

	return (true)
end
os.register("InitEvent", BaseEvent_Initialize)
