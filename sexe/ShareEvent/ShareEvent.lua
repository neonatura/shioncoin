-- ShareEvent [SRE3]
-- require 'BaseEvent'
ShareEvent = BaseEvent:Subclass();

local EVENT_REGISTER_VALUE = 100

local function ShareEvent_Initialize(arg)
	BaseEvent.data.Event.config["registerValue"] = EVENT_REGISTER_VALUE
end
os.register("InitEvent", ShareEvent_Initialize)
