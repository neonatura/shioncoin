-- Proposal 
--require 'BaseToken'

-- common time-spans
local ONE_MINUTE = 60
local THIRTY_DAYS = 2592000
local ONE_YEAR = 31536000

local MAX_QUORUM = 100
local MIN_QUORUM = 4 
local DEFAULT_QUORUM = 10

local DEBATE_PERIOD = 21600 -- 15 days in minutes

local ERR_INVAL = -22
local ERR_ALREADY = -114

-- number of tokens required per vote
local VOTE_VALUE = 1


-- send a proposal token to 'entity' and allow them to vote for yourself
function BaseProposal.newRepresentative(entity)
	-- transfer single token for representative to use
	return (BaseProposal.sendToken(entity, VOTE_VALUE))
end

-- create a new proposed context
function BaseProposal.newProposal(data, desc)
	-- return token to "treasury"
	local owner = BaseProposal.getOwner()
	if (BaseProposal.transferTo(owner, VOTE_VALUE) == false) then
		BaseProposal.setError("insufficient votes")
		return (false)
	end

	-- generate proposal id
	local p_id = BaseProposal.data.Proposal["INDEX"]
	BaseProposal.data.Proposal["INDEX"] = p_id + 1

	-- create proposal
	local p = {}
	p.id = p_id
	p.receiver = BaseProposal.getSentAddress()
	p.birth = BaseProposal.getSentTime()
	p.stamp = BaseProposal.getSentTime()
	p.data = data
	p.description = desc
	p.votes = { }
	BaseProposal.data.Proposal.proposals[p_id] = p

	return (BaseProposal.update())
end

function BaseProposal.getProposal(p_id)
	return (BaseProposal.data.Proposal.proposals[p_id])
end

function BaseProposal.vote(p_id, position)
	if (BaseProposal.balance() <= 0) then
		BaseProposal.setError("insufficient votes")
		return (false)
	end

	local p = BaseProposal.getProposal(p_id)
	if (p == nil) then
		return ERR_INVAL
	end

	position = tonumber(position)
	if (position > 0) then
		position = 1
	elseif (position < 0) then
		position = -1
	end

	-- record vote info 
	p.votes[sender] = position
	BaseProposal.data.Proposal.proposals[p_id] = p

	return (BaseProposal.update())
end

function BaseProposal.executeProposal(p_id, prop)
	if (p_id < 0) then
		return (false)
	end
	if (prop == nil) then
		return (false)
	end
--	if (msg.proposalID < 0 or msg.proposal >= BaseProposal.numProposals) then return (false) end

	local now = BaseProposal.getSentTime()
	local p = BaseProposal.data.Proposal.proposals[p_id]
	if (now > (p.birth + DEBATE_PERIOD)) then
		local q
		for i = 0, p.numVotes, 1 do
			q = q + (p.votes[i] * BaseProposal.balanceOf(p.voter[i]))
		end

		if (q > MIN_QUORUM) then
			local ctx_name = "vote:" .. p.hashCode
			local ctx_value = p
			if (BaseProposal.setContext(ctx_name, ctx_value) == false) then
				return (false)
			end
			BaseProposal.data.Proposal.accepted[p_id] = BaseProposal.getSentTime()
		end

		BaseProposal.data.Proposal.proposals[p_id] = nil
		return (BaseProposal.update())
	end

	-- debating period has not ended
	return false
end

local function BaseProposal.Initialize(arg)
	--
  if (BaseProposal.data == nil) then
    return false
  end

  if (BaseProposal.data.Proposal ~= nil) then
    -- already initialized
    return (true)
  end

	BaseProposal.data.Proposal = { }
	BaseProposal.data.Proposal["MIN_QUORUM"] = DEFAULT_QUORUM
	BaseProposal.data.Proposal["DEBATE_PERIOD"] = DEBATE_PERIOD
	BaseProposal.data.Proposal.proposals = {}
	BaseProposal.data.Proposal.accepted = {}
	BaseProposal.data.Proposal["INDEX"] = 0
end
os.register("InitProposal", BaseProposal_Initialize)
