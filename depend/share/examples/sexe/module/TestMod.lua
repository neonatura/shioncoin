-- load example "Settings" module
local function print(...) println(...) end
module (..., package.seeall)

require 'TestSettings'
Settings = nil

TestMod = {}
-- The same basic affect can be created by removing the module() and line above and adding the following..
--if TestMod then return end
--TestMod = {}
--local TestMod = TestMod

-- not required
TestMod._VERSION = "1.0"

function GetDefault(name)
	return (TestMod.defaults[name])
end

function Initialize()
	Settings = TestSettings:New()
	Settings:SetValue(OPT_COLOR, "red")
	print ("Color: " .. Settings:GetValue(OPT_COLOR));
	print ("Ping: " .. Settings:GetValue(OPT_PING));
end

