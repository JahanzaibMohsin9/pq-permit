// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PqcForge} from "@pqc-forge/PqcForge.sol";
import {PQPermit} from "../src/PQPermit.sol";
import {PQSig} from "@pqc-forge/PQSig.sol";
import {FestUSDLike} from "./mocks/Tokens.sol";

/// Random sequences of: relaying pre-signed (real ML-DSA-87) permits, spends, direct approvals, lockdowns,
/// nonce invalidations and time warps.
contract PermitHandler is Test {
    PQPermit public immutable pq;
    FestUSDLike public immutable token;
    address public immutable owner;
    address public immutable spender;
    address public immutable sink = address(0x5151);
    PQPermit.PermitSingle[] internal permits;
    bytes[] internal sigs;

    uint256 public ghostNonceMax;
    bool public ghostNonceDecreased;
    uint256 public ghostGranted; // sum of amounts granted to `spender` (permits + approvals)
    uint256 public ghostSpent; // sum actually pulled by `spender`

    constructor(PQPermit pq_, FestUSDLike token_, address owner_, address spender_, PQPermit.PermitSingle[] memory p, bytes[] memory s) {
        pq = pq_;
        token = token_;
        owner = owner_;
        spender = spender_;
        for (uint256 i; i < p.length; i++) {
            permits.push(p[i]);
            sigs.push(s[i]);
        }
    }

    function _track() internal {
        uint256 n = pq.nonces(owner);
        if (n < ghostNonceMax) ghostNonceDecreased = true;
        if (n > ghostNonceMax) ghostNonceMax = n;
    }

    function relay(uint256 i) external {
        i = bound(i, 0, permits.length - 1);
        try pq.permit(owner, permits[i], sigs[i]) {
            ghostGranted += permits[i].amount;
        } catch {}
        _track();
    }

    function spend(uint96 amount) external {
        amount = uint96(bound(amount, 1, 200e6));
        vm.prank(spender);
        try pq.transferFrom(owner, sink, uint160(amount), address(token)) {
            ghostSpent += amount;
        } catch {}
        _track();
    }

    function approve(uint96 amount) external {
        amount = uint96(bound(amount, 0, 100e6));
        vm.prank(owner);
        pq.approve(address(token), spender, uint160(amount), uint48(block.timestamp + 1 days));
        ghostGranted += amount;
        _track();
    }

    function lockdown() external {
        PQPermit.TokenSpender[] memory pairs = new PQPermit.TokenSpender[](1);
        pairs[0] = PQPermit.TokenSpender(address(token), spender);
        vm.prank(owner);
        pq.lockdown(pairs);
        _track();
    }

    function invalidate(uint16 jump) external {
        vm.prank(owner);
        try pq.invalidateNonces(pq.nonces(owner) + bound(jump, 1, 10)) {} catch {}
        _track();
    }

    function warp(uint32 dt) external {
        vm.warp(block.timestamp + bound(dt, 0, 6 hours));
    }
}

contract PQPermitInvariantTest is Test, PqcForge {
    PQPermit pq;
    FestUSDLike token;
    PermitHandler handler;
    address alice = makeAddr("alice");
    address spender = makeAddr("spender");

    function setUp() public {
        vm.chainId(9800);
        vm.warp(1_764_000_000);
        installPqc();
        pq = new PQPermit();
        token = new FestUSDLike();
        PqcKey memory k = pqcRegisterNew(alice, keccak256("alice"));
        token.mint(alice, 1_000_000e6);
        vm.prank(alice);
        token.approve(address(pq), type(uint256).max);
        (PQPermit.PermitSingle[] memory p, bytes[] memory s) = _presign(k);
        handler = new PermitHandler(pq, token, alice, spender, p, s);
        targetContract(address(handler));
    }

    function _presign(PqcKey memory k) internal returns (PQPermit.PermitSingle[] memory p, bytes[] memory s) {
        p = new PQPermit.PermitSingle[](4);
        s = new bytes[](4);
        for (uint256 i; i < 4; i++) {
            p[i] = PQPermit.PermitSingle({
                token: address(token),
                spender: spender,
                amount: uint160((i + 1) * 40e6),
                expiration: uint48(block.timestamp + 30 days),
                nonce: i,
                sigDeadline: block.timestamp + 30 days
            });
            s[i] = pqcSign(k, PQSig.messageBytes(pq.permitText(alice, p[i])));
        }
    }

    /// forge-config: default.invariant.runs = 16
    /// forge-config: default.invariant.depth = 24
    function invariant_nonceIsMonotonic() public view {
        assertFalse(handler.ghostNonceDecreased());
    }

    /// forge-config: default.invariant.runs = 16
    /// forge-config: default.invariant.depth = 24
    function invariant_spenderNeverPullsMoreThanGranted() public view {
        assertLe(handler.ghostSpent(), handler.ghostGranted());
        assertEq(token.balanceOf(handler.sink()), handler.ghostSpent());
    }
}
