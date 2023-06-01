// SPDX-License-Identifier: Unlicense
pragma solidity 0.8.20;

import "forge-std/Test.sol";
import {Offer, Swap} from "src/Swap.sol";
import {ERC20Mock} from "lib/openzeppelin-contracts/contracts//mocks/token/ERC20Mock.sol";
import {ECDSA} from "lib/solady/src/utils/ECDSA.sol";

contract SwapTest is Test {
    uint256 constant MAX_INT =
        0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;

    Swap swap;
    ERC20Mock offerMock;
    ERC20Mock considerationMock;

    Offer offer;

    bytes32 root;
    bytes32[] bobProof;
    bytes32[] charlieProof;

    uint256 expiration;
    uint96 nonce;

    uint256 alicePkey = 1;
    address alice = vm.addr(alicePkey);
    uint256 bobPkey = 2;
    address bob = vm.addr(bobPkey);
    uint256 charliePkey = 3;
    address charlie = vm.addr(charliePkey);
    uint256 dalePkey = 4;
    address dale = vm.addr(dalePkey);

    function setUp() public {
        swap = new Swap();

        offerMock = new ERC20Mock();
        considerationMock = new ERC20Mock();

        offerMock.mint(alice, 100 ether);
        considerationMock.mint(bob, 100 ether);
        considerationMock.mint(charlie, 100 ether);
        considerationMock.mint(dale, 100 ether);

        vm.prank(alice);
        offerMock.approve(address(swap), MAX_INT);
        vm.prank(bob);
        considerationMock.approve(address(swap), MAX_INT);
        vm.prank(charlie);
        considerationMock.approve(address(swap), MAX_INT);
        vm.prank(dale);
        considerationMock.approve(address(swap), MAX_INT);

        bytes32 bobLeaf = keccak256(abi.encodePacked(bob));
        bytes32 charlieLeaf = keccak256(abi.encodePacked(charlie));
        bobProof = new bytes32[](1);
        charlieProof = new bytes32[](1);
        bobProof[0] = charlieLeaf;
        charlieProof[0] = bobLeaf;
        root = keccak256(abi.encodePacked(charlieLeaf, bobLeaf));

        expiration = block.timestamp + 1 days;
        nonce = 0;

        offer = Offer(
            root,
            alice,
            nonce,
            address(offerMock),
            100 ether,
            address(considerationMock),
            100 ether,
            expiration
        );
    }

    function testExecuteOffer() public {
        bytes memory signature = _signOffer(offer, alicePkey);
        vm.prank(bob);
        swap.executeOffer(offer, signature, bobProof);

        assertEq(offerMock.balanceOf(bob), 100 ether);
        assertEq(considerationMock.balanceOf(alice), 100 ether);
    }

    function testExecuteOfferRevertSignature() public {
        bytes memory signature = _signOffer(offer, bobPkey);
        vm.prank(bob);
        vm.expectRevert(bytes("Invalid Signature"));
        swap.executeOffer(offer, signature, bobProof);

        assertEq(offerMock.balanceOf(alice), 100 ether);
        assertEq(considerationMock.balanceOf(bob), 100 ether);
    }

    function testExecuteOfferRevertProof() public {
        bytes memory signature = _signOffer(offer, alicePkey);
        vm.prank(dale);
        vm.expectRevert(bytes("Invalid Proof"));
        swap.executeOffer(offer, signature, bobProof);

        assertEq(offerMock.balanceOf(alice), 100 ether);
        assertEq(considerationMock.balanceOf(bob), 100 ether);
    }

    function testExecuteOfferRevertNonce() public {
        bytes memory signature = _signOffer(offer, alicePkey);

        vm.prank(bob);
        swap.executeOffer(offer, signature, bobProof);

        vm.prank(charlie);
        vm.expectRevert(bytes("Offer Invalid"));
        swap.executeOffer(offer, signature, charlieProof);

        assertEq(offerMock.balanceOf(bob), 100 ether);
        assertEq(considerationMock.balanceOf(alice), 100 ether);
        assertEq(considerationMock.balanceOf(charlie), 100 ether);
    }

    function testExecuteOfferRevertExpired() public {
        bytes memory signature = _signOffer(offer, alicePkey);
        vm.warp(expiration);

        vm.prank(bob);
        vm.expectRevert(bytes("Offer Expired"));
        swap.executeOffer(offer, signature, bobProof);

        assertEq(offerMock.balanceOf(alice), 100 ether);
        assertEq(considerationMock.balanceOf(bob), 100 ether);
    }

    function testExecuteOfferRevertCanceled() public {
        bytes memory signature = _signOffer(offer, alicePkey);
        vm.prank(alice);
        swap.cancelOffer(nonce);

        vm.prank(bob);
        vm.expectRevert(bytes("Offer Invalid"));
        swap.executeOffer(offer, signature, bobProof);

        assertEq(offerMock.balanceOf(alice), 100 ether);
        assertEq(considerationMock.balanceOf(bob), 100 ether);
    }

    function testExecuteOfferRevertAllowance() public {
        bytes memory signature = _signOffer(offer, alicePkey);
        vm.prank(alice);
        offerMock.approve(address(swap), 0);

        vm.prank(bob);
        vm.expectRevert();
        swap.executeOffer(offer, signature, bobProof);

        assertEq(offerMock.balanceOf(alice), 100 ether);
        assertEq(considerationMock.balanceOf(bob), 100 ether);
    }

    function _signOffer(
        Offer memory _offer,
        uint256 _pkey
    ) internal pure returns (bytes memory signature) {
        bytes32 digest = ECDSA.toEthSignedMessageHash(
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
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_pkey, digest);
        signature = abi.encodePacked(r, s, v);
    }
}
