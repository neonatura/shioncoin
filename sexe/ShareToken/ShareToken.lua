-- STO [SRT3]
--require 'BaseToken'
ShareToken = BaseToken:Subclass();

local TOKEN_SYMBOL = "STO"
local TOKEN_NAME = "Share Token"
local TOKEN_DECIMALS = 4
local TOTAL_SUPPLY = 1000000

-- tokens available for purchase
local EXCHANGE_TOTAL = 1000
local EXCHANGE_RATE = 0.01

-- The token exchange symbol.
function ShareToken.getSymbol()
	return TOKEN_SYMBOL
end

local function ShareToken_Initialize(arg)
	if (ShareToken.data == nil or ShareToken.data.Token == nil) then
		return (false)
	end

	local owner = ShareToken.getOwner()
	if (ShareToken.data.Token.balances[owner] == nil) then
		-- hard-coded variables
		ShareToken.data.Token.config["name"] = TOKEN_NAME
		ShareToken.data.Token.config["decimals"] = TOKEN_DECIMALS
		ShareToken.data.Token.config["totalSupply"] = TOTAL_SUPPLY
		ShareToken.data.Token.config["exchangeRate"] = EXCHANGE_RATE
		ShareToken.data.Token.config["exchangeTotal"] = EXCHANGE_TOTAL

		-- transfer all tokens to owner (init)
		ShareToken.data.Token.balances[owner] = TOTAL_SUPPLY
	end
	return (true)
end
os.register("InitEvent", ShareToken_Initialize)
