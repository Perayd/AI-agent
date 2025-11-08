// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/// @title AgentExecutor
/// @notice Verifies ECDSA-signed off-chain AI agent instructions and executes allowed actions (example: store / emit)
contract AgentExecutor {
    // mapping agent address => nonce to prevent replay
    mapping(address => uint256) public nonces;
    // owner for admin tasks
    address public owner;

    event AgentActionExecuted(address indexed agent, address indexed caller, string actionType, string payload);

    modifier onlyOwner() {
        require(msg.sender == owner, "only owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// @notice Admin: change owner
    function setOwner(address newOwner) external onlyOwner {
        owner = newOwner;
    }

    /// @notice Execute an agent action verified by a signature
    /// @param agent The expected signer (agent's address)
    /// @param actionType A short string describing action (e.g., "swap", "signal")
    /// @param payload JSON payload or data string (keep small to save gas)
    /// @param nonce Agent's nonce to prevent replay
    /// @param expiry Unix timestamp after which the signed instruction is invalid
    /// @param sig ECDSA signature (65 bytes: r,s,v concatenated)
    function executeAction(
        address agent,
        string calldata actionType,
        string calldata payload,
        uint256 nonce,
        uint256 expiry,
        bytes calldata sig
    ) external {
        require(block.timestamp <= expiry, "instruction expired");
        require(nonces[agent] == nonce, "invalid nonce");

        // recreate the signed message
        bytes32 messageHash = getMessageHash(agent, actionType, payload, nonce, expiry);
        address recovered = recoverSigner(messageHash, sig);
        require(recovered == agent, "invalid signature");

        // increment nonce
        nonces[agent] = nonce + 1;

        // Here you would do the actual action (e.g., call a DEX, move funds).
        // For safety, this example only emits an event so you can expand later.
        emit AgentActionExecuted(agent, msg.sender, actionType, payload);
    }

    /// @notice Hash the parameters in the same way the off-chain signer signs (EIP-191 style)
    function getMessageHash(
        address agent,
        string memory actionType,
        string memory payload,
        uint256 nonce,
        uint256 expiry
    ) public pure returns (bytes32) {
        // Use an unambiguous encoding. You can include chainId, contract address, etc for extra safety.
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(agent, actionType, payload, nonce, expiry))));
    }

    /// @notice Recover signer from signature
    function recoverSigner(bytes32 prefixedHash, bytes memory sig) public pure returns (address) {
        require(sig.length == 65, "sig wrong length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
        // EIP-2: s must be in lower half order, v must be 27 or 28 - omitted here for brevity (add in production)
        return ecrecover(prefixedHash, v, r, s);
    }
}
