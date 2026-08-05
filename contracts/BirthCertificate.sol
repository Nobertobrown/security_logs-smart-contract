// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title BirthCertificate
/// @notice Stores hashes of issued birth certificates on-chain and lets
///         anyone verify a certificate's integrity by comparing hashes.
/// @dev Educational project contract — minimal on purpose. No proxy pattern,
///      no multi-sig, no upgradeability. This is intentional for course scope.
contract BirthCertificate {
    enum Status { NonExistent, Valid, Revoked }

    struct Certificate {
        bytes32 certHash;
        address issuer;
        uint256 issuedAt;
        Status status;
    }


    address public owner;
    uint256 public issuanceFee;
    uint256 public verificationFee;

    mapping(string => Certificate) private certificates;

    event CertificateIssued(string indexed certId, bytes32 certHash, address indexed issuer, uint256 timestamp);
    event CertificateVerifiedRequest(string indexed certId, address indexed requester, uint256 timestamp);
    event CertificateRevoked(string indexed certId, uint256 timestamp);
    event FeesUpdated(uint256 newIssuanceFee, uint256 newVerificationFee);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized: owner only");
        _;
    }

    constructor(uint256 _issuanceFee, uint256 _verificationFee) {
        owner = msg.sender;
        issuanceFee = _issuanceFee;
        verificationFee = _verificationFee;
    }

    /// @notice Issue a new certificate record by paying the issuance fee.
    /// @dev Automatic issuance — no admin approval step, per project scope.
    /// @param certId Unique certificate identifier generated off-chain (e.g. UUID)
    /// @param certHash SHA-256 hash of the generated PDF (computed by backend)
    function issueCertificate(string calldata certId, bytes32 certHash) external payable {
        require(msg.value >= issuanceFee, "Insufficient issuance fee");
        require(certificates[certId].status == Status.NonExistent, "Certificate ID already exists");
        require(certHash != bytes32(0), "Hash cannot be empty");

        certificates[certId] = Certificate({
            certHash: certHash,
            issuer: msg.sender,
            issuedAt: block.timestamp,
            status: Status.Valid
        });

        emit CertificateIssued(certId, certHash, msg.sender, block.timestamp);
    }

    /// @notice Pay the verification fee. Emits an event; actual hash comparison
    ///         happens off-chain in the backend using getCertificate().
    /// @dev Kept separate from getCertificate() so that reading is free (view),
    ///      while the *act* of requesting a paid verification is recorded on-chain.
    function payVerificationFee(string calldata certId) external payable {
        require(msg.value >= verificationFee, "Insufficient verification fee");
        emit CertificateVerifiedRequest(certId, msg.sender, block.timestamp);
    }

    /// @notice Read a certificate's stored data. Free — no gas cost beyond the read itself.
    function getCertificate(string calldata certId)
        external
        view
        returns (bytes32 certHash, address issuer, uint256 issuedAt, Status status)
    {
        Certificate memory c = certificates[certId];
        return (c.certHash, c.issuer, c.issuedAt, c.status);
    }

    function revokeCertificate(string calldata certId) external onlyOwner {
        require(certificates[certId].status == Status.Valid, "Certificate not valid or does not exist");
        certificates[certId].status = Status.Revoked;
        emit CertificateRevoked(certId, block.timestamp);
    }

    function updateFees(uint256 _issuanceFee, uint256 _verificationFee) external onlyOwner {
        issuanceFee = _issuanceFee;
        verificationFee = _verificationFee;
        emit FeesUpdated(_issuanceFee, _verificationFee);
    }

    function withdraw() external onlyOwner {
        uint256 balance = address(this).balance;
        require(balance > 0, "Nothing to withdraw");
        (bool success, ) = payable(owner).call{value: balance}("");
        require(success, "Withdraw failed");
    }
}