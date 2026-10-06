// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IdentityBindFixture} from "./IdentityBindOnchainVerify.t.sol";
import {WithdrawalGateBound, WithdrawalGateVulnerable} from "../src/WithdrawalGate.sol";

/// The raw verifier accepting a receipt twice is not the bug. The bug is an
/// application that pays on every successful verify.
contract WithdrawalGateTest is IdentityBindFixture {
    function test_unbound_gate_pays_the_same_receipt_twice() public {
        WithdrawalGateVulnerable gate = new WithdrawalGateVulnerable(verifier, IMAGE_ID);
        bytes memory seal = abi.encodePacked(verifier.SELECTOR(), SEAL);
        gate.release(seal, JOURNAL);
        gate.release(seal, JOURNAL);
        assertEq(gate.released(), 200, "amount 100 paid twice");
    }

    function test_bound_gate_pays_once_even_if_the_seal_grows() public {
        WithdrawalGateBound gate = new WithdrawalGateBound(verifier, IMAGE_ID);
        bytes memory seal = abi.encodePacked(verifier.SELECTOR(), SEAL);
        assertEq(gate.release(seal, JOURNAL), 100);

        vm.expectRevert(bytes("SPENT"));
        gate.release(seal, JOURNAL);

        // Trailing byte changes the seal. The statement does not change, so
        // the nullifier is the same and the second shape does not pay again.
        vm.expectRevert(bytes("SPENT"));
        gate.release(abi.encodePacked(seal, bytes1(0xab)), JOURNAL);

        assertEq(gate.released(), 100);
    }

    /// The guest commits (receipt_id, owner, amount). No chain id. A nullifier
    /// on this deployment cannot see a second deployment.
    function test_committed_journal_has_no_chain_id() public pure {
        assertEq(JOURNAL.length, 24);
    }
}
