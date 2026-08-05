// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract SecurityLogChain {
    struct Block {
        uint256 index; 
        uint256 blockTimestamp;
        string eventType;
        string sourceIP;
        string severity;
        bytes32 hmacHash;
        bytes32 prevHash;
        bytes32 blockHash; 
    }

    Block[] public chain;
    address public owner;

    event LogAdded(
        uint256 indexed blockIndex,
        string eventType,
        string severity,
        bytes32 hmacHash,
        bytes32 blockHash
    );

    event ChainVerified(bool isValid, uint256 blocksChecked);

    modifier onlyOwner() {
        require(msg.sender == owner, "SecurityLogChain: caller is not owner");
        _;
    }

    constructor() {
        owner = msg.sender;

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

    function getBlock(uint256 _index) public view returns (Block memory) {
        require(_index < chain.length, "Block index out of range");
        return chain[_index];
    }

    function chainLength() public view returns (uint256) {
        return chain.length;
    }

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

    function verifyBlock(uint256 _index) public view returns (bool) {
        require(
            _index > 0 && _index < chain.length,
            "Invalid index for verification"
        );
        return chain[_index].prevHash == chain[_index - 1].blockHash;
    }

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
