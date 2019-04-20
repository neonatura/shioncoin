-- STO [SRT3]
require 'BaseToken'
ShionToken = BaseToken:Subclass();

local TOKEN_SYMBOL = "STO"
local TOKEN_NAME = "Shion Token"
local TOKEN_DECIMALS = 4
local TOTAL_SUPPLY = 1000000

local function ShionToken_Initialize(arg)
	local owner = ShionToken.getOwner()
	if (ShionToken.data.Token.balances[owner] == nil) then
		-- hard-coded variables
		ShionToken.data.Token["symbol"] = TOKEN_SYMBOL;
		ShionToken.data.Token["name"] = TOKEN_NAME
		ShionToken.data.Token["decimals"] = TOKEN_DECIMALS
		ShionToken.data.Token["totalSupply"] = TOTAL_SUPPLY

		-- transfer all tokens to owner (init)
		ShionToken.data.Token.balances[owner] = TOTAL_SUPPLY
	end
end
os.register("InitEvent", ShionToken_Initialize)
