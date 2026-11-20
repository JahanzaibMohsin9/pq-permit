// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {PqcForge} from "@pqc-forge/PqcForge.sol";
import {PQC_VERIFY} from "@pqc-forge/IQorePQC.sol";
import {PQPermit} from "../src/PQPermit.sol";
import {PQSig} from "@pqc-forge/PQSig.sol";
import {FestUSDLike} from "./mocks/Tokens.sol";

contract PQPermitTest is Test, PqcForge {
    PQPermit permit2;
    FestUSDLike token;
    PqcKey aliceKey;
    address alice = makeAddr("alice");
    address spender = makeAddr("spender");
    address relayer = makeAddr("relayer");
    address recipient = makeAddr("recipient");

    function setUp() public {
        vm.chainId(9800); // qorechain-diana
        vm.warp(1_764_000_000);
        installPqc();
        permit2 = new PQPermit();
        token = new FestUSDLike();
        aliceKey = pqcKeygen(keccak256("alice"));
        pqcRegister(alice, aliceKey.publicKey, true);
        token.mint(alice, 1_000e6);
        vm.prank(alice);
        token.approve(address(permit2), type(uint256).max); // one-time, window-protected tx
    }

    // ---------------------------------------------------------------- helpers

    function _permit(uint160 amount, uint256 nonce) internal view returns (PQPermit.PermitSingle memory) {
        return PQPermit.PermitSingle({
            token: address(token),
            spender: spender,
            amount: amount,
            expiration: uint48(block.timestamp + 1 days),
            nonce: nonce,
            sigDeadline: block.timestamp + 1 hours
        });
    }

    /// Exactly what QoreX signArbitrary signs: "qorechain-msg-v1|qorechain-diana|" + permitText.
    function _sign(PqcKey memory k, address owner, PQPermit.PermitSingle memory p) internal returns (bytes memory) {
        return pqcSign(k, PQSigHarness.messageBytes(permit2.permitText(owner, p)));
    }

    // ---------------------------------------------------------------- happy path

    function test_relayedPermitThenSpend() public {
        PQPermit.PermitSingle memory p = _permit(100e6, 0);
        bytes memory sig = _sign(aliceKey, alice, p);

        vm.prank(relayer); // anyone can relay; alice sends no transaction
        permit2.permit(alice, p, sig);

        (uint160 amount, uint48 exp) = permit2.allowance(alice, address(token), spender);
        assertEq(amount, 100e6);
        assertEq(exp, p.expiration);
        assertEq(permit2.nonces(alice), 1);

        vm.prank(spender);
        permit2.transferFrom(alice, recipient, 60e6, address(token));
        assertEq(token.balanceOf(recipient), 60e6);
        (amount,) = permit2.allowance(alice, address(token), spender);
        assertEq(amount, 40e6);
    }

    function test_unlimitedAllowanceIsNotDecremented() public {
        PQPermit.PermitSingle memory p = _permit(type(uint160).max, 0);
        permit2.permit(alice, p, _sign(aliceKey, alice, p));
        vm.prank(spender);
        permit2.transferFrom(alice, recipient, 500e6, address(token));
        (uint160 amount,) = permit2.allowance(alice, address(token), spender);
        assertEq(amount, type(uint160).max);
    }

    function test_permitTextIsHumanReadableAndFitsQoreX() public view {
        bytes memory text = permit2.permitText(alice, _permit(100e6, 0));
        console.log(string(text));
        assertLe(text.length, 4096); // QoreX signArbitrary limit
        assertEq(bytes12(text), bytes12("PQ Permit v1")); // must not start with the reserved "qorechain-"
    }

    // ---------------------------------------------------------------- forgery and replay

    function test_rejectsSignatureFromAnotherKey() public {
        PqcKey memory mallory = pqcKeygen(keccak256("mallory"));
        PQPermit.PermitSingle memory p = _permit(100e6, 0);
        bytes memory forged = _sign(mallory, alice, p);
        vm.expectRevert(PQPermit.InvalidSignature.selector);
        permit2.permit(alice, p, forged);
    }

    function test_rejectsTamperedAmount() public {
        PQPermit.PermitSingle memory p = _permit(100e6, 0);
        bytes memory sig = _sign(aliceKey, alice, p);
        p.amount = 1_000e6;
        vm.expectRevert(PQPermit.InvalidSignature.selector);
        permit2.permit(alice, p, sig);
    }

    function test_rejectsTamperedSpender() public {
        PQPermit.PermitSingle memory p = _permit(100e6, 0);
        bytes memory sig = _sign(aliceKey, alice, p);
        p.spender = relayer;
        vm.expectRevert(PQPermit.InvalidSignature.selector);
        permit2.permit(alice, p, sig);
    }

    function test_rejectsReplay() public {
        PQPermit.PermitSingle memory p = _permit(100e6, 0);
        bytes memory sig = _sign(aliceKey, alice, p);
        permit2.permit(alice, p, sig);
        vm.expectRevert(abi.encodeWithSelector(PQPermit.InvalidNonce.selector, 1, 0));
        permit2.permit(alice, p, sig);
    }

    function test_rejectsSignatureForAnotherOwner() public {
        address bob = makeAddr("bob");
        pqcRegister(bob, aliceKey.publicKey, true); // even the same key registered twice
        PQPermit.PermitSingle memory p = _permit(100e6, 0);
        bytes memory sig = _sign(aliceKey, alice, p);
        vm.expectRevert(PQPermit.InvalidSignature.selector);
        permit2.permit(bob, p, sig);
    }

    function test_rejectsCrossChainReplay() public {
        PQPermit.PermitSingle memory p = _permit(100e6, 0);
        bytes memory sig = _sign(aliceKey, alice, p); // signed for qorechain-diana
        vm.chainId(9801); // qorechain-vladi
        vm.expectRevert(PQPermit.InvalidSignature.selector);
        permit2.permit(alice, p, sig);
    }

    function test_rejectsSignatureForAnotherVerifierContract() public {
        PQPermit other = new PQPermit();
        PQPermit.PermitSingle memory p = _permit(100e6, 0);
        bytes memory sig = _sign(aliceKey, alice, p);
        vm.expectRevert(PQPermit.InvalidSignature.selector);
        other.permit(alice, p, sig);
    }

    function test_rejectsExpiredSignature() public {
        PQPermit.PermitSingle memory p = _permit(100e6, 0);
        bytes memory sig = _sign(aliceKey, alice, p);
        vm.warp(p.sigDeadline + 1);
        vm.expectRevert(abi.encodeWithSelector(PQPermit.SignatureExpired.selector, p.sigDeadline));
        permit2.permit(alice, p, sig);
    }

    // ---------------------------------------------------------------- key status rules

    function test_rejectsKeyWithoutPossessionProof() public {
        pqcRegister(alice, aliceKey.publicKey, false); // e.g. someone registered a copied public key
        PQPermit.PermitSingle memory p = _permit(100e6, 0);
        bytes memory sig = _sign(aliceKey, alice, p);
        vm.expectRevert(abi.encodeWithSelector(PQSig.PqcPossessionNotProven.selector, alice));
        permit2.permit(alice, p, sig);
    }

    function test_rejectsUnregisteredOwner() public {
        address carol = makeAddr("carol");
        PQPermit.PermitSingle memory p = _permit(100e6, 0);
        vm.expectRevert(abi.encodeWithSelector(PQSig.PqcKeyNotRegistered.selector, carol));
        permit2.permit(carol, p, hex"00");
    }

    /// On a network where the precompile is inactive, a call "succeeds" with empty return data.
    /// PQSig must fail closed instead of treating that as a valid signature.
    function test_failsClosedWhenPrecompileInactive() public {
        PQPermit.PermitSingle memory p = _permit(100e6, 0);
        bytes memory sig = _sign(aliceKey, alice, p);
        vm.etch(PQC_VERIFY, "");
        vm.expectRevert(abi.encodeWithSelector(PQSig.PqcPrecompileUnavailable.selector, PQC_VERIFY));
        permit2.permit(alice, p, sig);
    }

    // ---------------------------------------------------------------- allowance rules

    function test_allowanceExpires() public {
        PQPermit.PermitSingle memory p = _permit(100e6, 0);
        permit2.permit(alice, p, _sign(aliceKey, alice, p));
        vm.warp(uint256(p.expiration) + 1);
        vm.prank(spender);
        vm.expectRevert(abi.encodeWithSelector(PQPermit.AllowanceExpired.selector, p.expiration));
        permit2.transferFrom(alice, recipient, 1, address(token));
    }

    function test_cannotOverspend() public {
        PQPermit.PermitSingle memory p = _permit(100e6, 0);
        permit2.permit(alice, p, _sign(aliceKey, alice, p));
        vm.prank(spender);
        vm.expectRevert(abi.encodeWithSelector(PQPermit.InsufficientAllowance.selector, 100e6));
        permit2.transferFrom(alice, recipient, 100e6 + 1, address(token));
    }

    function test_onlySpenderCanSpend() public {
        PQPermit.PermitSingle memory p = _permit(100e6, 0);
        permit2.permit(alice, p, _sign(aliceKey, alice, p));
        vm.prank(relayer); // relayer has no allowance of its own
        vm.expectRevert(abi.encodeWithSelector(PQPermit.AllowanceExpired.selector, 0));
        permit2.transferFrom(alice, relayer, 1, address(token));
    }

    function test_invalidateNoncesCancelsPendingSignature() public {
        PQPermit.PermitSingle memory p = _permit(100e6, 0);
        bytes memory sig = _sign(aliceKey, alice, p);
        vm.prank(alice);
        permit2.invalidateNonces(1);
        vm.expectRevert(abi.encodeWithSelector(PQPermit.InvalidNonce.selector, 1, 0));
        permit2.permit(alice, p, sig);
    }

    function test_lockdown() public {
        PQPermit.PermitSingle memory p = _permit(100e6, 0);
        permit2.permit(alice, p, _sign(aliceKey, alice, p));
        PQPermit.TokenSpender[] memory pairs = new PQPermit.TokenSpender[](1);
        pairs[0] = PQPermit.TokenSpender(address(token), spender);
        vm.prank(alice);
        permit2.lockdown(pairs);
        vm.prank(spender);
        vm.expectRevert(abi.encodeWithSelector(PQPermit.InsufficientAllowance.selector, 0));
        permit2.transferFrom(alice, recipient, 1, address(token));
    }

    // ---------------------------------------------------------------- fuzz (no crypto: direct approvals)

    function testFuzz_allowanceAccounting(uint160 granted, uint160 spend1, uint160 spend2) public {
        granted = uint160(bound(granted, 0, 1_000e6));
        spend1 = uint160(bound(spend1, 0, granted));
        spend2 = uint160(bound(spend2, 0, 2_000e6));
        vm.prank(alice);
        permit2.approve(address(token), spender, granted, uint48(block.timestamp + 1));

        vm.prank(spender);
        permit2.transferFrom(alice, recipient, spend1, address(token));
        uint160 left = granted - spend1;

        vm.prank(spender);
        if (spend2 > left) {
            vm.expectRevert(abi.encodeWithSelector(PQPermit.InsufficientAllowance.selector, left));
            permit2.transferFrom(alice, recipient, spend2, address(token));
            assertEq(token.balanceOf(recipient), spend1);
        } else {
            permit2.transferFrom(alice, recipient, spend2, address(token));
            assertEq(token.balanceOf(recipient), uint256(spend1) + spend2);
        }
    }
}

/// Exposes the library's internal message builder to tests.
library PQSigHarness {
    function messageBytes(bytes memory data) internal view returns (bytes memory) {
        return PQSig.messageBytes(data);
    }
}
