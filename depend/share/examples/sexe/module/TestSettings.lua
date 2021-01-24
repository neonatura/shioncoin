require 'object'
TestSettings = object:Subclass();

OPT_COLOR = "color"
OPT_PING = "ping"

local settings = {}

local defaults = {
	[OPT_COLOR] = "blue",
	[OPT_PING] = "pong",
}

function TestSettings.GetOptions()
	return (settings);
end

function TestSettings:GetValue(name)
	return settings[name]
	end

function TestSettings:SetValue(name, value)
	settings[name] = value
end

function TestSettings:New()
	local obj = object.New(self)
	obj:Initialize()
	return (obj)
end

function TestSettings:Initialize()
	settings = defaults
end

