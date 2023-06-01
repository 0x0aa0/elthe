// SPDX-License-Identifier: Unlicense
pragma solidity 0.8.20;

import {ECDSA} from "lib/solady/src/utils/ECDSA.sol";
import {MerkleProofLib} from "lib/solady/src/utils/MerkleProofLib.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

/// @notice Offer struct to be signed by user offchain
struct Offer {
    /// Merkel root of acceptable counterparty addresses
    bytes32 counterpartyRoot;
    /// Address of offering party
    address offerer;
    /// Unique nonce of offer
    uint96 nonce;
    /// Address of token being offered
    address offerToken;
    /// Amount of token being offered
    uint96 offerAmount;
    /// Address of token to be received
    address considerationToken;
    /// Amount of token to be received
    uint96 considerationAmount;
    /// Timestamp when offer can no longer be executed
    uint256 expiration;
}

/// @title Swap
/// @author quaq.eth
/// @notice This contract conducts OTC swaps of ERC20 tokens bewteen two parties.
/// The contract operates by users signing offers offchain and counterparties
/// executing those offers onchain. The contract assumes that both parties have
/// given proper token allowances on their respective ERC20 contracts.
/// An advantage of this design is that given proper allowance swaps can be
/// executed in a single transaction by the counterparty, saving the offerer gas.
/// A drawback of this design is that counterparties can be exposed to low severity
/// greifing by attemping to execute invalid offers from a malicious offerer.

contract Swap {
    /// @dev Keep track of executed nonces to prevent replay attack
    mapping(address => mapping(uint96 => bool)) public executedNonce;

    /// @notice Function for counterparty to execute a ECDSA signed offer
    /// @param _offer the offer being executed
    /// @param _signature ECDSA signature from offerer
    /// @param _proof Merkle proof for executing counterparty
    function executeOffer(
        Offer memory _offer,
        bytes memory _signature,
        bytes32[] memory _proof
    ) external {
        /// Validate ECDSA signature
        _verifySignature(_offer, _signature);

        /// Validate Merkle proof
        _verifyProof(
            _proof,
            _offer.counterpartyRoot,
            keccak256(abi.encodePacked(msg.sender))
        );

        /// Validate offer is executed prior to expiration
        require(_offer.expiration > block.timestamp, "Offer Expired");

        /// Validate offer has not already been executed / invalidated
        require(!executedNonce[_offer.offerer][_offer.nonce], "Offer Invalid");

        /// Mark offer as executed to prevent reentrancy
        executedNonce[_offer.offerer][_offer.nonce] = true;

        /// Execute swap
        _execute(_offer);
    }

    /// @notice Function for offerer to invalidate an offer
    /// @param _nonce Nonce of offer to invalidate
    function cancelOffer(uint96 _nonce) external {
        executedNonce[msg.sender][_nonce] = true;
    }

    /// @dev Verification of ECDSA signature
    function _verifySignature(
        Offer memory _offer,
        bytes memory _signature
    ) internal view {
        /// Require that recovered signature matches the offerer
        require(
            ECDSA.recover(
                ECDSA.toEthSignedMessageHash(
                    keccak256(
                        abi.encodePacked(
                            _offer.counterpartyRoot,
                            _offer.offerer,
                            _offer.nonce,
                            _offer.offerToken,
                            _offer.offerAmount,
                            _offer.considerationToken,
                            _offer.considerationAmount,
                            _offer.expiration
                        )
                    )
                ),
                _signature
            ) == _offer.offerer,
            "Invalid Signature"
        );
    }

    /// @dev Verification of Merkle proof
    function _verifyProof(
        bytes32[] memory _proof,
        bytes32 _root,
        bytes32 _leaf
    ) internal pure {
        /// If Merkle root is 0 we assume that any counterparty can execute
        if (uint256(_root) > 0) {
            /// If Merkle proof is empty we assume one counterparty is stored as root
            if (_proof.length > 0) {
                /// Require that counterparty belongs to Merkle tree
                require(
                    MerkleProofLib.verify(_proof, _root, _leaf),
                    "Invalid Proof"
                );
            } else {
                require(_root == _leaf, "Invalid Proof");
            }
        }
    }

    /// @dev Execution of offer
    function _execute(Offer memory _offer) internal {
        /// Send offer from offerer to counterparty
        bool offerSuccess = IERC20(_offer.offerToken).transferFrom(
            _offer.offerer,
            msg.sender,
            uint256(_offer.offerAmount)
        );

        /// Send consideration from counterparty to offerer
        bool considerationSuccess = IERC20(_offer.considerationToken)
            .transferFrom(
                msg.sender,
                _offer.offerer,
                uint256(_offer.considerationAmount)
            );

        /// Require that both token transfers are successful
        require(offerSuccess && considerationSuccess, "Swap Not Successful");
    }
}
