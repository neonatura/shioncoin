-- PRIVTOK [SRT3]
--require 'BaseToken'
PrivateToken = BaseToken:Subclass();

local TOKEN_SYMBOL = "PRIVTOK"
local TOKEN_NAME = "Private Token"
local TOKEN_DECIMALS = 4
local TOTAL_SUPPLY = 1000000

-- tokens available for purchase
local EXCHANGE_TOTAL = 1000
local EXCHANGE_RATE = 0.01

local function PrivateToken_Initialize(arg)
	-- hard-coded variables
	PrivateToken.data.Token["symbol"] = TOKEN_SYMBOL;
	PrivateToken.data.Token["name"] = TOKEN_NAME
	PrivateToken.data.Token["decimals"] = TOKEN_DECIMALS
	PrivateToken.data.Token["totalSupply"] = TOTAL_SUPPLY

	PrivateToken.data.Token["exchangeRate"] = EXCHANGE_RATE
	PrivateToken.data.Token["exchangeTotal"] = EXCHANGE_TOTAL

	local owner = PrivateToken.getOwner()
	if (PrivateToken.data.Token.balances[owner] == nil) then
		-- transfer all tokens to owner (init)
		PrivateToken.data.Token.balances[owner] = TOTAL_SUPPLY
	end

	if (PrivateToken.isPerm(PERM_WHITELIST) == false) then
		if (PrivateToken.setPerm(PERM_WHITELIST) == false) then
			return (false)
		end
	end

	-- save whitelist 
	return (update())
end
os.register("InitEvent", PrivateToken_Initialize)
