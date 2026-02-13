// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20Like {
    function transferFrom(address from, address to, uint256 value) external returns (bool);
    function transfer(address to, uint256 value) external returns (bool);
}

contract MockRouter {
    event SwapExecuted(bytes32 indexed executionRef, address indexed sender, address indexed recipient, uint256 amountIn, uint256 amountOut);

    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts) {
        require(path.length >= 2, 'PATH');
        require(block.timestamp <= deadline, 'DEADLINE');

        address tokenIn = path[0];
        address tokenOut = path[path.length - 1];
        require(IERC20Like(tokenIn).transferFrom(msg.sender, address(this), amountIn), 'TRANSFER_IN');

        uint256 amountOut = amountIn;
        require(amountOut >= amountOutMin, 'SLIPPAGE');
        require(IERC20Like(tokenOut).transfer(to, amountOut), 'TRANSFER_OUT');

        bytes32 executionRef = keccak256(abi.encodePacked(msg.sender, to, tokenIn, tokenOut, amountIn, block.number));
        emit SwapExecuted(executionRef, msg.sender, to, amountIn, amountOut);

        amounts = new uint256[](2);
        amounts[0] = amountIn;
        amounts[1] = amountOut;
        return amounts;
    }
}
