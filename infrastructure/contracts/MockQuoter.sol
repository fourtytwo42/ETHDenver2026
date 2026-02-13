// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract MockQuoter {
    function quoteExactInputSingle(
        address,
        address,
        uint24,
        uint256 amountIn,
        uint160
    ) external pure returns (uint256 amountOut) {
        return amountIn;
    }
}
