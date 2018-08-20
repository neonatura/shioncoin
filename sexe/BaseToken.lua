-- token contract base (SRT3)
-- see 'ShareToken.lua' for example inheritance.

--require 'BaseObject'
require 'string'

BaseToken = BaseObject:Subclass();

-- this code attempts to be compatible with https://github.com/OpenZeppelin/zeppelin-solidity/tree/master/contracts/token/ERC20

local TOKEN_SYMBOL = "BTO"
local TOKEN_NAME = "Base Token"
local TOKEN_DECIMALS = 8
local TOTAL_SUPPLY = 1000000000

-- tokens available for purchase (ICO)
local EXCHANGE_TOTAL = 0
local EXCHANGE_RATE = 0.0

-- permissions
local PERM_WHITELIST = "whitelist"

function BaseToken.getSymbol()
	return TOKEN_SYMBOL
end

function BaseToken.getDecimals()
	return (BaseToken.data.Token.config["decimals"])
end

function BaseToken.getName()
	return (BaseToken.data.Token.config["name"])
end

function BaseToken.totalSupply()
	return (BaseToken.data.Token.config["totalSupply"])
end

function BaseToken.totalCapacity()
	return (BaseToken.data.Token.config["totalCapacity"])
end

function BaseToken.checkAddress(addr)
	if (addr == nil) then
		BaseToken.setError("coin address not specified")
		return false
	end
	if (string.len(addr) < 32 or string.len(addr) > 64) then
		BaseToken.setError("invalid coin address")
		return false
	end
	if (BaseToken.isWhitelist() == false) then
		BaseToken.setError("permission denied")
		return false
	end

	-- look'n good
	return true
end

-- the token balance for specified account
function BaseToken.balanceOf(tokenOwner)
	local bal = BaseToken.data.Token.balances[tokenOwner]
	if (bal == nil) then bal = 0 end
	return (bal)
end

-- the token balance for yourself account
function BaseToken.balance()
	return (BaseToken.balanceOf(BaseToken.getSentAddress()))
end

-- the amount of tokens approved to transfer to receiver from source
function BaseToken.allowance(source, receiver)
	if (BaseToken.checkAddress(source) == false or
			BaseToken.checkAddress(receiver) == false) then
		return (0)
	end

	if (BaseToken.data.Token.allowed[source] == nil) then
		return 0
	end
	if (BaseToken.data.Token.allowed[source][receiver] == nil) then
		return 0
	end

	return (BaseToken.data.Token.allowed[source][receiver])
end
--
-- the amount of tokens approved to transfer to yourself from source
function BaseToken.allowanceFrom(source)
	local receiver = BaseToken.getSentAddress()
	return (BaseToken.allowance(source, receiver))
end

-- permits 'receiver' to withdraw from yourself accounts
function BaseToken.approve(receiver, tokens)
	if (BaseToken.checkAddress(receiver) == false) then
		return (false)
	end

	-- sanity
	tokens = math.max(tonumber(tokens), 0)
	tokens = math.floor(tokens, BaseToken.getDecimals())

	-- update class data
	local source = BaseToken.getSentAddress()
	if (BaseToken.data.Token.allowed[source] == nil) then
		BaseToken.data.Token.allowed[source] = { }
	end
	BaseToken.data.Token.allowed[source][receiver] = tokens
	return (BaseToken.update())
end

function BaseToken.unapprove(receiver)
	return BaseToken.approve(receiver, 0)
end

-- decrease allowed tokens from yourself to receiver
function BaseToken.decrApproval(receiver, tokens)
	local source = BaseToken.getSentAddress()

	local val = 0
	if (BaseToken.data.Token.allowed[source] ~= nil and
			BaseToken.data.Token.allowed[source][receiver] ~= nil) then
		val = BaseToken.data.Token.allowed[source][receiver]
	end

	return (BaseToken.approve(receiver, val - tokens))
end

-- increase allowed tokens from yourself to receiver
function BaseToken.incrApproval(receiver, tokens)
	local source = BaseToken.getSentAddress()

	local val = 0
	if (BaseToken.data.Token.allowed[source] ~= nil and
			BaseToken.data.Token.allowed[source][receiver] ~= nil) then
		val = BaseToken.data.Token.allowed[source][receiver]
	end

	return (BaseToken.approve(receiver, val + tokens))
end

-- transfer token from sender account to receiver account
function BaseToken.transferTo(receiver, tokens)
	local source = BaseToken.getSentAddress()
	local totalSupply = BaseToken.totalSupply()

	tokens = math.max(0, tonumber(tokens))
	-- enforce limit of decimal precision
	tokens = math.floor(tokens, BaseToken.getDecimals())

	if (BaseToken.checkAddress(receiver) == false or
			tokens <= 0 or tokens > totalSupply) then
		-- invalid address(es) / token-value specified
		return (false)
	end
	if (source == receiver) then
		return (true)
	end

	local s_bal = BaseToken.data.Token.balances[source]
	if (s_bal == nil or s_bal < tokens) then
		-- invalid source or insufficient funds
		BaseToken.setError("insufficient funds")
		return (false)
	end
	BaseToken.data.Token.balances[source] = s_bal - tokens

	local r_bal = BaseToken.data.Token.balances[receiver]
	if (r_bal == nil) then r_bal = 0 end -- empty balance
	BaseToken.data.Token.balances[receiver] = r_bal + tokens

	-- store tx on blockchain
	return (BaseToken.update())
end

-- pre-permitted third-party transfer of own funds from source
function BaseToken.transferFrom(source, tokens)
	local receiver = BaseToken.getSentAddress()
	if (BaseToken.checkAddress(source) == false) then
		BaseToken.setError("invalid source address")
		return false
	end

	tokens = math.max(0, tonumber(tokens))
	if (BaseToken.data.Token.allowed[source] == nil) then
		BaseToken.setError("invalid source address")
		return false
	end
	local allow = BaseToken.data.Token.allowed[source][receiver]
	if (allow == nil or allow < tokens) then
		BaseToken.setError("insufficient allowance")
		return false
	end

	local s_bal = BaseToken.data.Token.balances[source]
	if (s_bal == nil or s_bal < tokens) then
		BaseToken.setError("receiver has insufficient funds")
		return false
	end

	-- allowance
	BaseToken.data.Token.allowed[source][receiver] = allow - tokens
	
	-- sub
	BaseToken.data.Token.balances[source] = s_bal - tokens

	-- add
	local r_bal = BaseToken.data.Token.balances[receiver]
	if (r_bal == nil) then r_bal = 0 end
	BaseToken.data.Token.balances[receiver] = r_bal + tokens

	-- store tx on blockchain
	return (BaseToken.update())
end

function BaseToken.transferOwnership(addr)
	if (isOwner() == false) then
		BaseToken.setError("permission denied")
		return (false);
	end

	-- update odule's user-data with new "owner" address.
	BaseToken.data["owner"] = addr
	return (BaseToken.update())
end

-- obtain summary info about your own account
function BaseToken.getInfo()
	local source = BaseToken.getSentAddress()
	local ret = { }
	
	-- coin symbol/name
	ret["symbol"] = BaseToken.getSymbol()
	ret["name"] = BaseToken.data.Token.config["name"] 
	ret["owner"] = BaseToken.getOwner()

	-- account address
	ret["sender"] = source

	-- account balance
	local bal = BaseToken.data.Token.balances[source]
	if (bal == nil) then bal = 0 end
	ret["balance"] = bal

	if (BaseToken.data.Token.config["exchangeTotal"] ~= 0) then
		ret["exchangeRate"] = BaseToken.data.Token.config["exchangeRate"]
		ret["exchangeTotal"] = BaseToken.data.Token.config["exchangeTotal"]
	end

	return (ret)
end

function BaseToken.purchaseToken()
	if (BaseToken.data.Token.config["exchangeTotal"] == 0) then
		BaseToken.setError("token purchase is disabled")
		return (false)
	end

	if (BaseToken.isOwner() == true) then
		BaseToken.setError("cannot purchase from self")
		return (false)
	end

	-- calculate tokens to send
	local xrate = math.max(0.00000001, BaseToken.data.Token.config["exchangeRate"])
	coins = math.max(0, BaseToken.getSentValue() - 0.0001) -- confirming tx fee
	local tokens = math.floor(coins * xrate, BaseToken.getDecimals())
	tokens = math.min(tokens, BaseToken.data.Token.config["exchangeTotal"])

	-- enforce precision
	coins = math.floor(tokens / xrate, 8)
	if (coins <= 0.0002 or tokens <= 0.00000001) then
		BaseToken.setError("insufficient funds")
		return (false)
	end

	local owner = BaseToken.getOwner()
	local bal = BaseToken.data.Token.balances[owner]
	if (bal == nil or bal < tokens) then
		-- owner has insufficient tokens to exchange
		BaseToken.setError("insufficient tokens available")
		return (false)
	end

	-- deduct cost
	if (BaseToken.incrFee(coins) == false) then
		BaseToken.setError("insufficient funds available")
	end

	-- record transferred tokens
	local source = BaseToken.getSentAddress()
	local s_val = BaseToken.data.Token.balances[source]
	if (s_val == nil) then s_val = 0 end
	BaseToken.data.Token.balances[source] = s_val + tokens;

	BaseToken.data.Token.balances[owner] = BaseToken.data.Token.balances[owner] - tokens;

	-- subtract available coins for purchase
	BaseToken.data.Token.config["exchangeTotal"] = 
			BaseToken.data.Token.config["exchangeTotal"] - tokens

	-- commit transaction
	return (BaseToken.update())
end

function BaseToken.getExchangeTotal()
	return (BaseToken.data.Token.config["exchangeTotal"])
end

function BaseToken.getExchangeRate()
	if (BaseToken.data.Token.config["exchangeTotal"] == 0) then
		-- disabled
		return (0)
	end
	return (BaseToken.data.Token.config["exchangeRate"])
end

function BaseToken.setWhitelist(addr)
	if (BaseToken.isPerm(PERM_WHITELIST) == false) then
		BaseToken.setError("whitelist not supported");
		return false
	end

	return (BaseToken.setPerm(PERM_WHITELIST, addr))
end

function BaseToken.unsetWhitelist(addr)
	if (BaseToken.isPerm(PERM_WHITELIST) == false) then
		BaseToken.setError("whitelist not supported");
		return false
	end

	return (BaseToken.unsetPerm(PERM_WHITELIST, addr))
end

function BaseToken.isWhitelist()
	if (BaseToken.isPerm(PERM_WHITELIST) == false) then
		-- whitelist not enabled -- all addresses permitted
		return true
	end

	return (BaseToken.hasPerm(PERM_WHITELIST))
end

function BaseToken.burn(tokens)
	tokens = math.max(0, tonumber(tokens))

	-- reduce balance
	local source = BaseToken.getSentAddress()
	local bal = BaseToken.data.Token.balances[source]
	if (bal == nil) then bal = 0 end
	if (bal < tokens) then
		BaseToken.setError("insufficient tokens")
		return (false)
	end
	BaseToken.data.Token.balances[source] = bal - tokens

	-- reduce total supply
	local tot = BaseToken.data.Token.config["totalSupply"]
	BaseToken.data.Token.config["totalSupply"] = tot - tokens 

	return (BaseToken.update())
end

function BaseToken.canMint()
	if (BaseToken.totalSupply() >= BaseToken.totalCapacity()) then
		BaseToken.setError("minting not available")
		return (false)
	end

	return (true)
end

function BaseToken.mint(tokens)
	if (BaseToken.totalSupply() + tokens >= BaseToken.totalCapacity()) then
		BaseToken.setError("minting not available")
		return (false)
	end
	if (BaseToken.isAdmin() == false) then
		BaseToken.setError("permission denied")
		return (false)
	end

	local source = BaseToken.getSentAddress()
	local bal = BaseToken.data.Token.balances[source]
	if (bal == nil) then bal = 0 end
	BaseToken.data.Token.balances[source] = bal + tokens

	-- increase total supply
	local tot = BaseToken.data.Token.config["totalSupply"]
	BaseToken.data.Token.config["totalSupply"] = tot + tokens 

	return (BaseToken.update())
end

local function BaseToken_Initialize(arg)
  --
	if (BaseToken.data == nil) then
		return (false)
	end
	if (BaseToken.data.Token ~= nil) then
		-- already initialized
		return (true)
	end

	-- initialize data structure 
	BaseToken.data.Token = { }
	BaseToken.data.Token.balances = {}
	BaseToken.data.Token.allowed = {}
	BaseToken.data.Token.config = {}
	BaseToken.data.Token.config["name"] = TOKEN_NAME
	BaseToken.data.Token.config["decimals"] = TOKEN_DECIMALS
	BaseToken.data.Token.config["totalSupply"] = TOTAL_SUPPLY
	BaseToken.data.Token.config["exchangeTotal"] = EXCHANGE_TOTAL
	BaseToken.data.Token.config["exchangeRate"] = EXCHANGE_RATE

	-- mintable coins (default: disabled)
	BaseToken.data.Token.config["totalCapacity"] = 0
	return (true);
end
os.register("InitEvent", BaseToken_Initialize)
