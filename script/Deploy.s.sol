// SPDX-License-Identifier: Unlicense
pragma solidity 0.8.20;

import {Script} from "forge-std/Script.sol";
import {Swap} from "src/Swap.sol";

contract Deploy is Script {
    function run() external {
        vm.startBroadcast();
        new Swap();
        vm.stopBroadcast();
    }
}
