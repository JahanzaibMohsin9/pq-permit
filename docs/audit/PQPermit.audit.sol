// SPDX-License-Identifier: MIT
// PQ Permit: audit bundle = IQorePQC.sol + PQSig.sol (pqc-forge) + PQPermit.sol, concatenated in one file.
// OpenZeppelin v5.4.0 imports are left as imports (unmodified library code).
// Repo: https://github.com/JahanzaibMohsin9/pq-permit
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

// ===== lib/pqc-forge/src/IQorePQC.sol =====

// QoreChain post-quantum EVM precompiles (active on testnet qorechain-diana).
// Source: qorechain-core docs/EVM_PRECOMPILES.md. Behaviour notes that differ from the docs
//      were measured against the live testnet and are encoded in the pqc-forge mocks.
address constant PQC_VERIFY = 0x0000000000000000000000000000000000000a01;
address constant PQC_KEY_STATUS = 0x0000000000000000000000000000000000000a02;

uint256 constant MLDSA87_PUBKEY_LEN = 2592;
uint256 constant MLDSA87_SIG_LEN = 4627;

interface IPqcVerify {
    /// Pure ML-DSA-87 (FIPS-204, empty context, no prehash). Returns false on a bad signature or wrong sizes.
    function pqcVerify(bytes calldata pubkey, bytes calldata signature, bytes calldata message)
        external
        view
        returns (bool);
}

interface IPqcKeyStatus {
    function pqcKeyStatus(address account)
        external
        view
        returns (bool registered, uint8 algorithmId, bytes memory pubkey, bool possessionProven);
}

// ===== lib/pqc-forge/src/PQSig.sol =====


/// @title PQSig
/// @notice Fail-closed helpers around QoreChain's ML-DSA-87 precompiles.
/// @dev Safety rules, each one learned from the live chain or the docs:
///  - A precompile that is inactive (e.g. mainnet today) returns success with EMPTY return data.
///    A naive `abi.decode` would revert by accident, and a hand-rolled check might read it as "true".
///    We require exactly 32 bytes back, or we revert.
///  - If the call runs out of gas the call fails but the caller carries on, so we revert in that case.
///  - A registered key is not enough: a copied public key passes `registered`.
///    We require `possessionProven` and algorithmId 1 (ML-DSA-87).
///  - Messages use the QoreSign message-signing-v1 domain:
///    "qorechain-msg-v1|" + cosmosChainId + "|" + data
///    so the bytes are exactly what QoreX `signArbitrary` signs, and can't be replayed as a tx.
///  - INTEGRATORS: never wrap these calls in try/catch and treat a revert as "invalid signature" (or as
///    valid). A relayer can starve a precompile call of gas (63/64 rule) to force a revert; reverting the
///    whole transaction is the only safe outcome.
library PQSig {
    uint8 internal constant ALG_MLDSA87 = 1;

    error PqcPrecompileUnavailable(address precompile);
    error PqcKeyNotRegistered(address account);
    error PqcPossessionNotProven(address account);
    error PqcUnsupportedAlgorithm(address account, uint8 algorithmId);
    error UnknownChain(uint256 chainId);

    /// @notice The ML-DSA-87 public key registered on chain for `account`, with possession proven.
    function registeredKey(address account) internal view returns (bytes memory pubkey) {
        (bool ok, bytes memory ret) =
            PQC_KEY_STATUS.staticcall(abi.encodeCall(IPqcKeyStatus.pqcKeyStatus, (account)));
        if (!ok || ret.length < 128) revert PqcPrecompileUnavailable(PQC_KEY_STATUS);
        bool registered;
        uint8 alg;
        bool proven;
        (registered, alg, pubkey, proven) = abi.decode(ret, (bool, uint8, bytes, bool));
        if (!registered) revert PqcKeyNotRegistered(account);
        if (alg != ALG_MLDSA87) revert PqcUnsupportedAlgorithm(account, alg);
        if (!proven) revert PqcPossessionNotProven(account);
    }

    /// @notice Raw ML-DSA-87 verification. Reverts if the precompile is unavailable; never returns a false positive.
    function verify(bytes memory pubkey, bytes memory signature, bytes memory message) internal view returns (bool) {
        (bool ok, bytes memory ret) =
            PQC_VERIFY.staticcall(abi.encodeCall(IPqcVerify.pqcVerify, (pubkey, signature, message)));
        if (!ok || ret.length != 32) revert PqcPrecompileUnavailable(PQC_VERIFY);
        return abi.decode(ret, (bool));
    }

    /// @notice Verify `signature` by `account`'s registered key over QoreSign message bytes for `data`.
    function verifyMessageBy(address account, bytes memory data, bytes memory signature) internal view returns (bool) {
        return verify(registeredKey(account), signature, messageBytes(data));
    }

    /// @notice QoreSign message-signing-v1 bytes: "qorechain-msg-v1|" + chain_id + "|" + data.
    function messageBytes(bytes memory data) internal view returns (bytes memory) {
        return bytes.concat("qorechain-msg-v1|", bytes(cosmosChainId()), "|", data);
    }

    /// @notice Cosmos chain id for the current EVM chain id.
    function cosmosChainId() internal view returns (string memory) {
        if (block.chainid == 9800) return "qorechain-diana";
        if (block.chainid == 9801) return "qorechain-vladi";
        revert UnknownChain(block.chainid);
    }
}

// ===== src/PQPermit.sol =====


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
    error InvalidExpiration(uint48 expiration);
    error NonceJumpTooLarge();

    /// Max nonce advance per invalidation, and what `lockdown` advances by (cancels every signed, unrelayed permit).
    uint256 public constant MAX_NONCE_JUMP = type(uint16).max;

    /// @notice Grant `p.spender` an allowance over `owner`'s `p.token`, authorised by an ML-DSA-87 signature.
    ///         Callable by anyone (relayer, spender, owner).
    /// @dev Like Permit2, anyone may relay a permit first; integrators bundling `permit` + an action should
    ///      tolerate an `InvalidNonce` revert when the allowance is already in place (front-run griefing).
    function permit(address owner, PermitSingle calldata p, bytes calldata signature) external {
        if (block.timestamp > p.sigDeadline) revert SignatureExpired(p.sigDeadline);
        if (p.expiration < block.timestamp) revert InvalidExpiration(p.expiration);
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
        if (expiration < block.timestamp) revert InvalidExpiration(expiration);
        allowance[msg.sender][token][spender] = Allowance(amount, expiration);
        emit Approval(msg.sender, token, spender, amount, expiration);
    }

    /// @notice Emergency stop: zero out allowances AND cancel every signed-but-unrelayed permit
    ///         (advances the nonce by MAX_NONCE_JUMP, so no pending signature can re-arm an allowance).
    function lockdown(TokenSpender[] calldata pairs) external {
        for (uint256 i; i < pairs.length; ++i) {
            allowance[msg.sender][pairs[i].token][pairs[i].spender].amount = 0;
            emit Lockdown(msg.sender, pairs[i].token, pairs[i].spender);
        }
        uint256 newNonce = nonces[msg.sender] + MAX_NONCE_JUMP;
        nonces[msg.sender] = newNonce;
        emit NonceInvalidation(msg.sender, newNonce);
    }

    /// @notice Cancel every unused signed permit with a nonce below `newNonce` (at most MAX_NONCE_JUMP ahead,
    ///         so an owner can never brick their own nonce space).
    function invalidateNonces(uint256 newNonce) external {
        uint256 current = nonces[msg.sender];
        if (newNonce <= current) revert NonceNotIncreasing();
        if (newNonce - current > MAX_NONCE_JUMP) revert NonceJumpTooLarge();
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

