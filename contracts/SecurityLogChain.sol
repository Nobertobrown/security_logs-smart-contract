// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title  SecurityLogChain
 * @notice Immutable blockchain ledger for security log events.
 *         Each block stores a log entry signed with HMAC-SHA256
 *         using the analyst's registration number (230242452779)
 *         as the secret key.  The HMAC digest is computed off-chain
 *         (see hmac_signer.py) and stored on-chain for verification.
 *
 * @dev    Designed for Remix IDE  (solidity ^0.8.19)
 *         Deploy on:  Remix VM (Cancun) / Sepolia testnet
 *
 * ── ARCHITECTURE ──────────────────────────────────────────────────
 *  Layer 1: Raw log events (SQL Injection, XSS, Brute Force, etc.)
 *  Layer 2: HMAC-SHA256 signing  key = "230242452779" (off-chain)
 *  Layer 3: This smart contract  (on-chain immutable storage)
 *  Layer 4: verifyChain() / verifyBlock() for integrity checks
 * ──────────────────────────────────────────────────────────────────
 *
 * REGISTRATION NUMBER  : 230242452779
 * HMAC ALGORITHM       : HMAC-SHA256
 * BLOCK HASH ALGORITHM : keccak256  (native Solidity)
 */
contract SecurityLogChain {
    // ─────────────────────────────────────────────────────────────
    // DATA STRUCTURES
    // ─────────────────────────────────────────────────────────────

    struct Block {
        uint256 index; // sequential block number (0 = genesis)
        uint256 blockTimestamp; // Unix epoch when block was mined
        string eventType; // e.g. "SQL_INJECTION", "XSS_ATTEMPT"
        string sourceIP; // attacker's source IP (or "N/A")
        string severity; // "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
        bytes32 hmacHash; // HMAC-SHA256(key=regNum, msg=logData)  — off-chain
        bytes32 prevHash; // hash of the preceding block
        bytes32 blockHash; // keccak256 of this block's core fields
    }

    // ─────────────────────────────────────────────────────────────
    // STATE
    // ─────────────────────────────────────────────────────────────

    Block[] public chain;
    address public owner;

    // ─────────────────────────────────────────────────────────────
    // EVENTS  (emitted so front-ends / explorers can index them)
    // ─────────────────────────────────────────────────────────────

    event LogAdded(
        uint256 indexed blockIndex,
        string eventType,
        string severity,
        bytes32 hmacHash,
        bytes32 blockHash
    );

    event ChainVerified(bool isValid, uint256 blocksChecked);

    // ─────────────────────────────────────────────────────────────
    // MODIFIERS
    // ─────────────────────────────────────────────────────────────

    modifier onlyOwner() {
        require(msg.sender == owner, "SecurityLogChain: caller is not owner");
        _;
    }

    // ─────────────────────────────────────────────────────────────
    // CONSTRUCTOR — creates the genesis block
    // ─────────────────────────────────────────────────────────────

    constructor() {
        owner = msg.sender;

        // Genesis block: all hashes are zero
        // The genesis block establishes the initial state of the chain and provides a known starting point for integrity verification. 
        // It ensures that there is a block with index 0 and a defined prevHash (zero) for the first real log block to reference. 
        // This simplifies the logic for adding new blocks and verifying the chain, as every block (including the first real log) can uniformly reference its predecessor without special cases.
        bytes32 genesisHash = keccak256(
            abi.encodePacked(
                uint256(0),
                block.timestamp,
                bytes32(0),
                bytes32(0)
            )
        );

        chain.push(
            Block({
                index: 0,
                blockTimestamp: block.timestamp,
                eventType: "GENESIS",
                sourceIP: "0.0.0.0",
                severity: "NONE",
                hmacHash: bytes32(0),
                prevHash: bytes32(0),
                blockHash: genesisHash
            })
        );

        emit LogAdded(0, "GENESIS", "NONE", bytes32(0), genesisHash);
    }

    // ─────────────────────────────────────────────────────────────
    // WRITE — add a new security log entry as a block
    // ─────────────────────────────────────────────────────────────

    /**
     * @notice  Add a security log event to the chain.
     * @param   _eventType  Short identifier, e.g. "SQL_INJECTION"
     * @param   _sourceIP   Attacker source IP address string
     * @param   _severity   "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
     * @param   _hmacHash   HMAC-SHA256 digest computed off-chain
     *                      using key = "230242452779"
     *
     * @dev     The block hash is keccak256 of
     *          (index, timestamp, _hmacHash, prevHash).
     *          This links every block cryptographically to its predecessor.
     */
    function addLog(
        string memory _eventType,
        string memory _sourceIP,
        string memory _severity,
        bytes32 _hmacHash
    ) public onlyOwner {
        require(bytes(_eventType).length > 0, "eventType cannot be empty");
        require(bytes(_severity).length > 0, "severity cannot be empty");

        uint256 newIndex = chain.length;
        bytes32 prevHash = chain[newIndex - 1].blockHash;

        bytes32 blockHash = keccak256(
            abi.encodePacked(newIndex, block.timestamp, _hmacHash, prevHash)
        );

        chain.push(
            Block({
                index: newIndex,
                blockTimestamp: block.timestamp,
                eventType: _eventType,
                sourceIP: _sourceIP,
                severity: _severity,
                hmacHash: _hmacHash,
                prevHash: prevHash,
                blockHash: blockHash
            })
        );

        emit LogAdded(newIndex, _eventType, _severity, _hmacHash, blockHash);
    }

    // ─────────────────────────────────────────────────────────────
    // READ — retrieve a block
    // ─────────────────────────────────────────────────────────────

    /**
     * @notice  Return all fields of a block by index.
     */
    function getBlock(uint256 _index) public view returns (Block memory) {
        require(_index < chain.length, "Block index out of range");
        return chain[_index];
    }

    /**
     * @notice  Return total number of blocks in the chain (including genesis).
     */
    function chainLength() public view returns (uint256) {
        return chain.length;
    }

    // ─────────────────────────────────────────────────────────────
    // VERIFY — integrity checks
    // ─────────────────────────────────────────────────────────────

    /**
     * @notice  Walk every block and confirm that each block's prevHash
     *          matches the hash of the preceding block.
     *          Returns true only if the entire chain is intact.
     *
     * @dev     NOTE: This does NOT re-compute HMAC — that must be
     *          done off-chain (see hmac_signer.py verify_hmac()).
     *          This function only checks the on-chain linkage.
     */
    function verifyChain() public returns (bool) {
        uint256 len = chain.length;
        if (len <= 1) {
            emit ChainVerified(true, len);
            return true;
        }

        for (uint256 i = 1; i < len; i++) {
            if (chain[i].prevHash != chain[i - 1].blockHash) {
                emit ChainVerified(false, i);
                return false;
            }
        }

        emit ChainVerified(true, len);
        return true;
    }

    /**
     * @notice  Verify the linkage of a single block against its predecessor.
     * @param   _index  Index of the block to verify (must be >= 1).
     */
    function verifyBlock(uint256 _index) public view returns (bool) {
        require(
            _index > 0 && _index < chain.length,
            "Invalid index for verification"
        );
        return chain[_index].prevHash == chain[_index - 1].blockHash;
    }

    /**
     * @notice  Re-compute a block's hash from its stored fields and
     *          compare to the stored blockHash.
     *          Useful to detect any storage-level corruption.
     *
     * @dev     The timestamp used at mining time is stored in blockTimestamp.
     *          We use that stored value — not block.timestamp — for recomputation.
     */
    function recomputeBlockHash(uint256 _index) public view returns (bytes32) {
        require(_index < chain.length, "Block index out of range");
        Block memory b = chain[_index];
        return
                        keccak256(
                abi.encodePacked(
                    b.index,
                    b.blockTimestamp,
                    b.hmacHash,
                    b.prevHash
                )
            );
    }

    // ─────────────────────────────────────────────────────────────
    // BULK LOADER (convenience — add all 10 logs in one tx call
    //             from a script or Remix "At Address" panel)
    // ─────────────────────────────────────────────────────────────

    /**
     * @notice  Seed the chain with all 10 real log events.
     *          HMAC digests were computed by hmac_signer.py using
     *          registration number "230242452779" as the secret key.
     *
     * @dev     Call this ONCE immediately after deployment.
     *          The function is restricted to owner.
     */
    function seedAllLogs() external onlyOwner {
        require(chain.length == 1, "Logs already seeded");

        addLog(
            "SQL_INJECTION",
            "41.59.200.20",
            "HIGH",
            0xeaea411e36064e32a3bf1e42cec1cc669191ee2a3ef23eeeef14d480170f5d44
        );

        addLog(
            "BRUTE_FORCE",
            "102.45.78.22",
            "MEDIUM",
            0x92fcbe9e8b9312f5feb3223a50440d1039a03fc3ea7778256108e5ed08128436
        );

        addLog(
            "XSS_ATTEMPT",
            "196.200.55.10",
            "HIGH",
            0xef7fe50fdbed303f1d1241dd564f47d5d589c6157a1128c219676a49b658bb44
        );

        addLog(
            "UNAUTHORIZED_API_ACCESS",
            "154.118.220.15",
            "HIGH",
            0x1d36eaca8fabdb3116b6dd34648f14c3d8e4e06517d8b1f03eb515253901ec5f
        );

        addLog(
            "SMS_API_ABUSE",
            "41.222.15.90",
            "HIGH",
            0xed45af0bb2a76b86f48a7a96cda5bc1ed0ed6b8f10b1e2cc2ce35015318886d8
        );

        addLog(
            "CREDENTIAL_STUFFING",
            "185.10.20.30",
            "HIGH",
            0x248bfa9650c679fe80cecef5ee0005ae12b52c31924604fbec49812ad7f40f41
        );

        addLog(
            "PRIVILEGE_ESCALATION",
            "102.67.89.55",
            "CRITICAL",
            0x3b7fbf0844065a192af185b85544856cbdb30903959e7cb22004c9fa5ea14504
        );

        addLog(
            "GEOLOCATION_ANOMALY",
            "N/A",
            "HIGH",
            0x22572d609d1cfc1e1ad757104ce00582a8e28aa30cdc2493aa6775bc1b8f2afd
        );

        addLog(
            "DOS_RATE_LIMIT",
            "203.0.113.45",
            "HIGH",
            0xa2ee549c12ade4edd421ed1e13eb6d2522f2dcdb0422249b1628ba30c6f8ba33
        );

        addLog(
            "SENSITIVE_CONFIG_ACCESS",
            "198.51.100.20",
            "CRITICAL",
            0x4cc599b6dc5de7c541f6047f4625899a6e585e8db58d7c30ef713a9c4d3362ca
        );
    }
}
