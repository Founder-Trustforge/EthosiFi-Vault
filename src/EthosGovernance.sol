// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

interface IEthosStaking {
    function isMVP(address account) external view returns (bool);
    function getGovernanceVotes(address account) external view returns (uint256);
}

/**
 * @title EthosGovernance
 * @notice On-chain governance for EthosiFi Vault MVP token holders
 * @dev
 * Voting power = $ETHOS staked / 1000 (1 vote per 1000 $ETHOS)
 * Proposals require minimum quorum to pass
 * Timelocked execution after passing
 *
 * Governance categories:
 * - FEATURE: New security module prioritization
 * - CHAIN: Chain expansion (Base, Polygon, Arbitrum, Solana)
 * - THREAT: Threat registry governance
 * - TREASURY: Treasury allocation
 * - PARAMETER: Fee/burn rate adjustments
 *
 * EthosiFi Vault — The Unstealable Wallet
 */
contract EthosGovernance {

    IEthosStaking public immutable stakingContract;
    address public owner;

    // ─── CONSTANTS ───────────────────────────────────────────────────────────

    uint256 public constant VOTING_PERIOD    = 7 days;
    uint256 public constant TIMELOCK_PERIOD  = 2 days;
    uint256 public constant QUORUM_VOTES     = 100; // Minimum 100 votes to pass
    uint256 public constant MIN_MVP_TO_PROPOSE = 1;  // Must be MVP to propose

    // ─── ENUMS ───────────────────────────────────────────────────────────────

    enum ProposalCategory { FEATURE, CHAIN, THREAT, TREASURY, PARAMETER }
    enum ProposalStatus   { ACTIVE, PASSED, REJECTED, EXECUTED, CANCELLED }

    // ─── STATE ───────────────────────────────────────────────────────────────

    struct Proposal {
        uint256             id;
        address             proposer;
        string              title;
        string              description;
        ProposalCategory    category;
        ProposalStatus      status;
        uint256             votesFor;
        uint256             votesAgainst;
        uint256             startTime;
        uint256             endTime;
        uint256             executionTime;
        bool                executed;
        bytes               callData;    // Optional: encoded function call
        address             target;      // Optional: contract to call on execution
    }

    uint256 public proposalCount;
    mapping(uint256 => Proposal) public proposals;

    // proposalId => voter => hasVoted
    mapping(uint256 => mapping(address => bool)) public hasVoted;

    // proposalId => voter => votesUsed
    mapping(uint256 => mapping(address => uint256)) public votesUsed;

    // ─── EVENTS ──────────────────────────────────────────────────────────────

    event ProposalCreated(
        uint256 indexed proposalId,
        address indexed proposer,
        string title,
        ProposalCategory category,
        uint256 endTime
    );
    event VoteCast(
        address indexed voter,
        uint256 indexed proposalId,
        bool support,
        uint256 votes
    );
    event ProposalPassed(uint256 indexed proposalId, uint256 votesFor, uint256 votesAgainst);
    event ProposalRejected(uint256 indexed proposalId, uint256 votesFor, uint256 votesAgainst);
    event ProposalExecuted(uint256 indexed proposalId);
    event ProposalCancelled(uint256 indexed proposalId);

    // ─── ERRORS ──────────────────────────────────────────────────────────────

    error NotOwner();
    error NotMVP();
    error ProposalNotActive();
    error AlreadyVoted();
    error VotingEnded();
    error VotingNotEnded();
    error TimelockNotMet();
    error AlreadyExecuted();
    error ProposalNotPassed();
    error NoVotingPower();

    // ─── CONSTRUCTOR ─────────────────────────────────────────────────────────

    constructor(address _stakingContract) {
        stakingContract = IEthosStaking(_stakingContract);
        owner = msg.sender;
    }

    // ─── PROPOSAL FUNCTIONS ──────────────────────────────────────────────────

    /**
     * @notice Create a governance proposal
     * @dev Proposer must be an active MVP member
     */
    function createProposal(
        string calldata title,
        string calldata description,
        ProposalCategory category,
        address target,
        bytes calldata callData
    ) external returns (uint256 proposalId) {
        if (!stakingContract.isMVP(msg.sender)) revert NotMVP();

        proposalId = ++proposalCount;

        proposals[proposalId] = Proposal({
            id:            proposalId,
            proposer:      msg.sender,
            title:         title,
            description:   description,
            category:      category,
            status:        ProposalStatus.ACTIVE,
            votesFor:      0,
            votesAgainst:  0,
            startTime:     block.timestamp,
            endTime:       block.timestamp + VOTING_PERIOD,
            executionTime: block.timestamp + VOTING_PERIOD + TIMELOCK_PERIOD,
            executed:      false,
            callData:      callData,
            target:        target
        });

        emit ProposalCreated(proposalId, msg.sender, title, category, block.timestamp + VOTING_PERIOD);
    }

    /**
     * @notice Cast a vote on a proposal
     * @param proposalId Proposal to vote on
     * @param support True = vote for, False = vote against
     */
    function castVote(uint256 proposalId, bool support) external {
        if (!stakingContract.isMVP(msg.sender)) revert NotMVP();

        Proposal storage p = proposals[proposalId];
        if (p.status != ProposalStatus.ACTIVE) revert ProposalNotActive();
        if (block.timestamp > p.endTime) revert VotingEnded();
        if (hasVoted[proposalId][msg.sender]) revert AlreadyVoted();

        uint256 votes = stakingContract.getGovernanceVotes(msg.sender);
        if (votes == 0) revert NoVotingPower();

        hasVoted[proposalId][msg.sender] = true;
        votesUsed[proposalId][msg.sender] = votes;

        if (support) {
            p.votesFor += votes;
        } else {
            p.votesAgainst += votes;
        }

        emit VoteCast(msg.sender, proposalId, support, votes);
    }

    /**
     * @notice Finalize a proposal after voting period ends
     */
    function finalizeProposal(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        if (p.status != ProposalStatus.ACTIVE) revert ProposalNotActive();
        if (block.timestamp <= p.endTime) revert VotingNotEnded();

        uint256 totalVotes = p.votesFor + p.votesAgainst;

        if (p.votesFor > p.votesAgainst && totalVotes >= QUORUM_VOTES) {
            p.status = ProposalStatus.PASSED;
            emit ProposalPassed(proposalId, p.votesFor, p.votesAgainst);
        } else {
            p.status = ProposalStatus.REJECTED;
            emit ProposalRejected(proposalId, p.votesFor, p.votesAgainst);
        }
    }

    /**
     * @notice Execute a passed proposal after timelock
     */
    function executeProposal(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        if (p.status != ProposalStatus.PASSED) revert ProposalNotPassed();
        if (p.executed) revert AlreadyExecuted();
        if (block.timestamp < p.executionTime) revert TimelockNotMet();

        p.executed = true;
        p.status = ProposalStatus.EXECUTED;

        // Execute on-chain call if target specified
        if (p.target != address(0) && p.callData.length > 0) {
            (bool success,) = p.target.call(p.callData);
            require(success, "Execution failed");
        }

        emit ProposalExecuted(proposalId);
    }

    // ─── VIEW FUNCTIONS ──────────────────────────────────────────────────────

    function getProposal(uint256 proposalId) external view returns (Proposal memory) {
        return proposals[proposalId];
    }

    function getVotingPower(address account) external view returns (uint256) {
        return stakingContract.getGovernanceVotes(account);
    }

    function getActiveProposals() external view returns (uint256[] memory) {
        uint256 count;
        for (uint256 i = 1; i <= proposalCount; i++) {
            if (proposals[i].status == ProposalStatus.ACTIVE &&
                block.timestamp <= proposals[i].endTime) count++;
        }

        uint256[] memory active = new uint256[](count);
        uint256 idx;
        for (uint256 i = 1; i <= proposalCount; i++) {
            if (proposals[i].status == ProposalStatus.ACTIVE &&
                block.timestamp <= proposals[i].endTime) {
                active[idx++] = i;
            }
        }
        return active;
    }

    // ─── OWNER FUNCTIONS ─────────────────────────────────────────────────────

    function cancelProposal(uint256 proposalId) external {
        if (msg.sender != owner) revert NotOwner();
        Proposal storage p = proposals[proposalId];
        if (p.status != ProposalStatus.ACTIVE) revert ProposalNotActive();
        p.status = ProposalStatus.CANCELLED;
        emit ProposalCancelled(proposalId);
    }

    function transferOwnership(address newOwner) external {
        if (msg.sender != owner) revert NotOwner();
        owner = newOwner;
    }
}
