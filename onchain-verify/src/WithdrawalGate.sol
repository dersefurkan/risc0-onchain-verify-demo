// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IRiscZeroVerifier} from "risc0-ethereum/contracts/src/IRiscZeroVerifier.sol";

/// @notice Pays the journal amount every time the seal verifies.
/// The verifier is stateless, so the same receipt releases the amount again.
/// Teaching contract — not for production.
contract WithdrawalGateVulnerable {
    IRiscZeroVerifier public immutable verifier;
    bytes32 public immutable imageId;
    uint256 public released;

    constructor(IRiscZeroVerifier verifier_, bytes32 imageId_) {
        verifier = verifier_;
        imageId = imageId_;
    }

    function release(bytes calldata seal, bytes calldata journal)
        external
        returns (uint256 amount)
    {
        verifier.verify(seal, imageId, sha256(journal));
        amount = _amount(journal);
        released += amount;
    }

    function _amount(bytes calldata journal) internal pure returns (uint256) {
        require(journal.length == 24, "JOURNAL");
        uint256 amount;
        for (uint256 i = 0; i < 8; i++) {
            amount |= uint256(uint8(journal[16 + i])) << (8 * i);
        }
        return amount;
    }
}

/// @notice Same payment, one nullifier. The key is `(imageId, journalDigest)`,
/// not the seal bytes. A longer seal of the same statement hits the same key.
///
/// This stops a second payment on THIS deployment. The committed journal is
/// three u64s and does not contain a chain id, so the same receipt still
/// verifies on a fresh deployment. Binding the chain is a guest change.
contract WithdrawalGateBound {
    IRiscZeroVerifier public immutable verifier;
    bytes32 public immutable imageId;
    uint256 public released;
    mapping(bytes32 => bool) public spent;

    constructor(IRiscZeroVerifier verifier_, bytes32 imageId_) {
        verifier = verifier_;
        imageId = imageId_;
    }

    function release(bytes calldata seal, bytes calldata journal)
        external
        returns (uint256 amount)
    {
        bytes32 digest = sha256(journal);
        verifier.verify(seal, imageId, digest);
        bytes32 id = keccak256(abi.encode(imageId, digest));
        require(!spent[id], "SPENT");
        spent[id] = true;
        amount = _amount(journal);
        released += amount;
    }

    function _amount(bytes calldata journal) internal pure returns (uint256) {
        require(journal.length == 24, "JOURNAL");
        uint256 amount;
        for (uint256 i = 0; i < 8; i++) {
            amount |= uint256(uint8(journal[16 + i])) << (8 * i);
        }
        return amount;
    }
}
