-- STO [SRT3]
require 'BaseToken'
ShareToken = BaseToken:Subclass();

local TOKEN_SYMBOL = "STO"
local TOKEN_NAME = "Share Token"
local TOKEN_DECIMALS = 4
local TOTAL_SUPPLY = 1000000

local function ShareToken_Initialize(arg)
	local owner = ShareToken.getOwner()
	if (ShareToken.data.Token.balances[owner] == nil) then
		-- hard-coded variables
		ShareToken.data.Token["symbol"] = TOKEN_SYMBOL;
		ShareToken.data.Token["name"] = TOKEN_NAME
		ShareToken.data.Token["decimals"] = TOKEN_DECIMALS
		ShareToken.data.Token["totalSupply"] = TOTAL_SUPPLY

		-- transfer all tokens to owner (init)
		ShareToken.data.Token.balances[owner] = TOTAL_SUPPLY
	end
end
os.register("InitEvent", ShareToken_Initialize)
