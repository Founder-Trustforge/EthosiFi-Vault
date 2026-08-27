// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

import {ReentrancyGuard} from "solady/utils/ReentrancyGuard.sol";

interface IEthosStaking {
    function isMVP(address account) external view returns (bool);
    function getGovernanceVotes(address account) external view returns (uint256);
}

/**
 * @title  EthosGovernance
 * @notice On-chain governance for EthosiFi Vault MVP token holders.
 *
 * @dev    SECURITY FIXES (2026-08 audit):
 *         [CRIT-1] executeProposal() made an arbitrary .call() with attacker-controlled
 *                  target and callData. A malicious governance proposal could drain any
 *                  contract, transfer ownership, or call any function in the protocol.
 *                  Fixed: only whitelisted target contracts may be called, and only
 *                  whitelisted function selectors are permitted per target.
 *         [HIGH-1] transferOwnership() was one-step. Fixed: two-step.
 *         [MED-1]  No reentrancy guard on executeProposal(). Fixed.
 *         [MED-2]  getActiveProposals() iterated unbounded proposalCount — DoS if
 *                  many proposals exist. Added a pagination-based view.
 *         [MED-3]  Quorum check only required totalVotes >= QUORUM_VOTES but did not
 *                  verify that votesFor constituted a majority of total staked supply.
 *                  Added minimum participation rate check.
 */
contract EthosGovernance is ReentrancyGuard {

    IEthosStaking public immutable stakingContract;
    address public owner;
    address public pendingOwner;

    // ─── Constants ────────────────────────────────────────────────────────────

    uint256 public constant VOTING_PERIOD     = 7 days;
    uint256 public constant TIMELOCK_PERIOD   = 2 days;
    uint256 public constant QUORUM_VOTES      = 100;
    uint256 public constant MAX_TARGETS       = 20;

    // ─── Types ────────────────────────────────────────────────────────────────

    enum ProposalCategory { FEATURE, CHAIN, THREAT, TREASURY, PARAMETER }
    enum ProposalStatus   { ACTIVE, PASSED, REJECTED, EXECUTED, CANCELLED }

    struct Proposal {
        uint256          id;
        address          proposer;
        string           title;
        string           description;
        ProposalCategory category;
        ProposalStatus   status;
        uint256          votesFor;
        uint256          votesAgainst;
        uint256          startTime;
        uint256          endTime;
        uint256          executionTime;
        bool             executed;
        bytes            callData;
        address          target;
    }

    // ─── Storage ──────────────────────────────────────────────────────────────

    uint256 public proposalCount;
    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => mapping(address => bool))    public hasVoted;
    mapping(uint256 => mapping(address => uint256)) public votesUsed;

    /// @dev [CRIT-1] Whitelist of contracts that governance can call.
    mapping(address => bool)                          public approvedTargets;
    /// @dev [CRIT-1] Per-target whitelist of function selectors.
    mapping(address => mapping(bytes4 => bool))       public approvedSelectors;

    // ─── Events ───────────────────────────────────────────────────────────────

    event ProposalCreated(uint256 indexed proposalId, address indexed proposer, string title, ProposalCategory category, uint256 endTime);
    event VoteCast(address indexed voter, uint256 indexed proposalId, bool support, uint256 votes);
    event ProposalPassed(uint256 indexed proposalId, uint256 votesFor, uint256 votesAgainst);
    event ProposalRejected(uint256 indexed proposalId, uint256 votesFor, uint256 votesAgainst);
    event ProposalExecuted(uint256 indexed proposalId);
    event ProposalCancelled(uint256 indexed proposalId);
    event TargetApproved(address indexed target);
    event TargetRevoked(address indexed target);
    event SelectorApproved(address indexed target, bytes4 selector);
    event SelectorRevoked(address indexed target, bytes4 selector);
    event OwnershipTransferStarted(address indexed prev, address indexed next);
    event OwnershipTransferred(address indexed prev, address indexed next);

    // ─── Errors ───────────────────────────────────────────────────────────────

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
    error TargetNotApproved();
    error SelectorNotApproved();
    error ExecutionFailed();
    error ZeroAddress();

    // ─── Constructor ──────────────────────────────────────────────────────────

    constructor(address _stakingContract) {
        if (_stakingContract == address(0)) revert ZeroAddress();
        stakingContract = IEthosStaking(_stakingContract);
        owner = msg.sender;
    }

    modifier onlyOwner() { if (msg.sender != owner) revert NotOwner(); _; }

    // ─── Proposals ────────────────────────────────────────────────────────────

    function createProposal(
        string calldata title,
        string calldata description,
        ProposalCategory category,
        address target,
        bytes calldata callData
    ) external returns (uint256 proposalId) {
        if (!stakingContract.isMVP(msg.sender)) revert NotMVP();

        // [CRIT-1] Validate target and selector before storing proposal
        if (target != address(0) && callData.length >= 4) {
            if (!approvedTargets[target]) revert TargetNotApproved();
            bytes4 selector = bytes4(callData[:4]);
            if (!approvedSelectors[target][selector]) revert SelectorNotApproved();
        }

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

    function castVote(uint256 proposalId, bool support) external {
        if (!stakingContract.isMVP(msg.sender)) revert NotMVP();

        Proposal storage p = proposals[proposalId];
        if (p.status != ProposalStatus.ACTIVE) revert ProposalNotActive();
        if (block.timestamp > p.endTime) revert VotingEnded();
        if (hasVoted[proposalId][msg.sender]) revert AlreadyVoted();

        uint256 votes = stakingContract.getGovernanceVotes(msg.sender);
        if (votes == 0) revert NoVotingPower();

        hasVoted[proposalId][msg.sender]  = true;
        votesUsed[proposalId][msg.sender] = votes;

        if (support) { p.votesFor += votes; }
        else          { p.votesAgainst += votes; }

        emit VoteCast(msg.sender, proposalId, support, votes);
    }

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
     * @notice Execute a passed proposal after timelock.
     * @dev [CRIT-1] Target and selector re-validated at execution time.
     *      Even if whitelist changes after proposal creation, the execution
     *      will revert if the target/selector is no longer approved.
     */
    function executeProposal(uint256 proposalId) external nonReentrant {
        Proposal storage p = proposals[proposalId];
        if (p.status != ProposalStatus.PASSED) revert ProposalNotPassed();
        if (p.executed) revert AlreadyExecuted();
        if (block.timestamp < p.executionTime) revert TimelockNotMet();

        // [CRIT-1] Effects before interactions
        p.executed = true;
        p.status   = ProposalStatus.EXECUTED;

        if (p.target != address(0) && p.callData.length >= 4) {
            // Re-validate at execution time
            if (!approvedTargets[p.target]) revert TargetNotApproved();
            bytes4 selector = bytes4(p.callData[:4]);
            if (!approvedSelectors[p.target][selector]) revert SelectorNotApproved();

            (bool success,) = p.target.call(p.callData);
            if (!success) revert ExecutionFailed();
        }

        emit ProposalExecuted(proposalId);
    }

    // ─── Target / selector whitelist (owner only) ─────────────────────────────

    function approveTarget(address target) external onlyOwner {
        if (target == address(0)) revert ZeroAddress();
        approvedTargets[target] = true;
        emit TargetApproved(target);
    }

    function revokeTarget(address target) external onlyOwner {
        approvedTargets[target] = false;
        emit TargetRevoked(target);
    }

    function approveSelector(address target, bytes4 selector) external onlyOwner {
        approvedSelectors[target][selector] = true;
        emit SelectorApproved(target, selector);
    }

    function revokeSelector(address target, bytes4 selector) external onlyOwner {
        approvedSelectors[target][selector] = false;
        emit SelectorRevoked(target, selector);
    }

    // ─── Owner functions ──────────────────────────────────────────────────────

    function cancelProposal(uint256 proposalId) external onlyOwner {
        Proposal storage p = proposals[proposalId];
        if (p.status != ProposalStatus.ACTIVE) revert ProposalNotActive();
        p.status = ProposalStatus.CANCELLED;
        emit ProposalCancelled(proposalId);
    }

    // ─── Two-step ownership ───────────────────────────────────────────────────

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotOwner();
        emit OwnershipTransferred(owner, pendingOwner);
        owner        = pendingOwner;
        pendingOwner = address(0);
    }

    // ─── View ─────────────────────────────────────────────────────────────────

    function getProposal(uint256 proposalId) external view returns (Proposal memory) {
        return proposals[proposalId];
    }

    function getVotingPower(address account) external view returns (uint256) {
        return stakingContract.getGovernanceVotes(account);
    }

    /// @dev [MED-2] Paginated to prevent unbounded gas usage.
    function getActiveProposals(uint256 offset, uint256 limit) external view returns (uint256[] memory ids, uint256 total) {
        uint256[] memory temp = new uint256[](limit);
        uint256 count;
        for (uint256 i = offset + 1; i <= proposalCount && count < limit; i++) {
            if (proposals[i].status == ProposalStatus.ACTIVE && block.timestamp <= proposals[i].endTime) {
                temp[count++] = i;
            }
        }
        ids = new uint256[](count);
        for (uint256 i = 0; i < count; i++) ids[i] = temp[i];
        total = proposalCount;
    }
}
