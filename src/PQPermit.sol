// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {PQSig} from "@pqc-forge/PQSig.sol";

/// @title PQ Permit
/// @notice Gasless token approvals signed with ML-DSA-87 instead of ECDSA.
/// @dev Permit2-style: the owner approves this contract once on the token (an ordinary tx, protected by
///      their EVM window). After that, spending allowances are granted by off-chain ML-DSA-87 signatures
///      that anyone may relay. A leaked ECDSA key cannot produce them.
///      The signed text is human-readable, so a wallet can show the user exactly what they approve.
contract PQPermit {
    using SafeERC20 for IERC20;
    using Strings for address;
    using Strings for uint256;

    struct Allowance {
        uint160 amount; // type(uint160).max = unlimited
        uint48 expiration; // unix seconds, inclusive
    }

    struct PermitSingle {
        address token;
        address spender;
        uint160 amount;
        uint48 expiration;
        uint256 nonce;
        uint256 sigDeadline;
    }

    struct TokenSpender {
        address token;
        address spender;
    }

    mapping(address owner => mapping(address token => mapping(address spender => Allowance))) public allowance;
    mapping(address owner => uint256) public nonces;

    event Permit(
        address indexed owner,
        address indexed token,
        address indexed spender,
        uint160 amount,
        uint48 expiration,
        uint256 nonce
    );
    event Approval(address indexed owner, address indexed token, address indexed spender, uint160 amount, uint48 expiration);
    event Lockdown(address indexed owner, address token, address spender);
    event NonceInvalidation(address indexed owner, uint256 newNonce);

    error SignatureExpired(uint256 sigDeadline);
    error InvalidNonce(uint256 expected, uint256 got);
    error InvalidSignature();
    error AllowanceExpired(uint48 expiration);
    error InsufficientAllowance(uint160 available);
    error NonceNotIncreasing();

    /// @notice Grant `p.spender` an allowance over `owner`'s `p.token`, authorised by an ML-DSA-87 signature.
    ///         Callable by anyone (relayer, spender, owner).
    function permit(address owner, PermitSingle calldata p, bytes calldata signature) external {
        if (block.timestamp > p.sigDeadline) revert SignatureExpired(p.sigDeadline);
        uint256 expected = nonces[owner];
        if (p.nonce != expected) revert InvalidNonce(expected, p.nonce);
        if (!PQSig.verifyMessageBy(owner, permitText(owner, p), signature)) revert InvalidSignature();

        nonces[owner] = expected + 1;
        allowance[owner][p.token][p.spender] = Allowance(p.amount, p.expiration);
        emit Permit(owner, p.token, p.spender, p.amount, p.expiration, p.nonce);
    }

    /// @notice Spend from an allowance. `msg.sender` must be the approved spender.
    function transferFrom(address owner, address to, uint160 amount, address token) external {
        Allowance storage a = allowance[owner][token][msg.sender];
        if (block.timestamp > a.expiration) revert AllowanceExpired(a.expiration);
        if (a.amount != type(uint160).max) {
            if (amount > a.amount) revert InsufficientAllowance(a.amount);
            unchecked {
                a.amount -= amount;
            }
        }
        IERC20(token).safeTransferFrom(owner, to, amount);
    }

    /// @notice Direct approval by the owner's own (window-protected) transaction.
    function approve(address token, address spender, uint160 amount, uint48 expiration) external {
        allowance[msg.sender][token][spender] = Allowance(amount, expiration);
        emit Approval(msg.sender, token, spender, amount, expiration);
    }

    /// @notice Emergency: zero out allowances.
    function lockdown(TokenSpender[] calldata pairs) external {
        for (uint256 i; i < pairs.length; ++i) {
            allowance[msg.sender][pairs[i].token][pairs[i].spender].amount = 0;
            emit Lockdown(msg.sender, pairs[i].token, pairs[i].spender);
        }
    }

    /// @notice Cancel every unused signed permit with a nonce below `newNonce`.
    function invalidateNonces(uint256 newNonce) external {
        if (newNonce <= nonces[msg.sender]) revert NonceNotIncreasing();
        nonces[msg.sender] = newNonce;
        emit NonceInvalidation(msg.sender, newNonce);
    }

    /// @notice The exact human-readable text the owner signs (the `data` in QoreSign message-signing-v1).
    /// @dev Binds chain, this contract, owner, token, spender, amount, expiry, nonce and deadline.
    function permitText(address owner, PermitSingle calldata p) public view returns (bytes memory) {
        return bytes.concat(
            "PQ Permit v1\n",
            "chain: ", bytes(block.chainid.toString()), "\n",
            "verifier: ", bytes(address(this).toHexString()), "\n",
            "owner: ", bytes(owner.toHexString()), "\n",
            "token: ", bytes(p.token.toHexString()), "\n",
            "spender: ", bytes(p.spender.toHexString()), "\n",
            "amount: ", bytes(_amount(p.amount)), "\n",
            "allowance expires: ", bytes(uint256(p.expiration).toString()), "\n",
            "nonce: ", bytes(p.nonce.toString()), "\n",
            "signature valid until: ", bytes(p.sigDeadline.toString())
        );
    }

    function _amount(uint160 amount) private pure returns (string memory) {
        return amount == type(uint160).max ? "unlimited" : uint256(amount).toString();
    }
}
