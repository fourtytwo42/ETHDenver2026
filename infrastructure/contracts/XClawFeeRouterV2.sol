// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20Like {
    function balanceOf(address owner) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 value) external returns (bool);
    function transfer(address to, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

interface IV2RouterLike {
    function getAmountsOut(uint256 amountIn, address[] calldata path) external view returns (uint256[] memory amounts);

    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);
}

/// @notice Non-upgradeable V2-compatible router proxy that takes a 50 bps fee on output token.
/// Semantics:
/// - getAmountsOut returns net amounts (post-fee on final output).
/// - swapExactTokensForTokens enforces amountOutMin against net-to-user (post-fee).
contract XClawFeeRouterV2 {
    uint16 public constant FEE_BPS = 50; // 0.5%
    uint16 private constant BPS_DENOM = 10000;

    address public immutable dexRouter;
    address public immutable treasury;

    // Simple nonReentrant guard.
    uint256 private _entered;

    event FeeTaken(
        address indexed token,
        address indexed payer,
        address indexed treasury,
        uint256 feeAmount,
        uint256 grossOut,
        uint256 netOut
    );

    constructor(address dexRouter_, address treasury_) {
        require(dexRouter_ != address(0), "ROUTER_ZERO");
        require(treasury_ != address(0), "TREASURY_ZERO");
        dexRouter = dexRouter_;
        treasury = treasury_;
    }

    modifier nonReentrant() {
        require(_entered == 0, "REENTRANT");
        _entered = 1;
        _;
        _entered = 0;
    }

    function getAmountsOut(uint256 amountIn, address[] calldata path) external view returns (uint256[] memory amounts) {
        amounts = IV2RouterLike(dexRouter).getAmountsOut(amountIn, path);
        if (amounts.length == 0) {
            return amounts;
        }
        uint256 grossOut = amounts[amounts.length - 1];
        uint256 fee = _feeFromGross(grossOut);
        amounts[amounts.length - 1] = grossOut - fee;
        return amounts;
    }

    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external nonReentrant returns (uint256[] memory amounts) {
        require(path.length >= 2, "PATH");
        require(block.timestamp <= deadline, "DEADLINE");
        require(to != address(0), "TO_ZERO");

        address tokenIn = path[0];
        address tokenOut = path[path.length - 1];

        _safeTransferFrom(tokenIn, msg.sender, address(this), amountIn);
        _safeApproveExact(tokenIn, dexRouter, amountIn);

        uint256 balBefore = IERC20Like(tokenOut).balanceOf(address(this));
        // Call underlying router with recipient=this so we can take fee atomically.
        amounts = IV2RouterLike(dexRouter).swapExactTokensForTokens(amountIn, 0, path, address(this), deadline);
        uint256 balAfter = IERC20Like(tokenOut).balanceOf(address(this));
        require(balAfter >= balBefore, "BALANCE_DELTA");
        uint256 grossOut = balAfter - balBefore;

        uint256 fee = _feeFromGross(grossOut);
        uint256 netOut = grossOut - fee;
        require(netOut >= amountOutMin, "SLIPPAGE_NET");

        if (fee > 0) {
            _safeTransfer(tokenOut, treasury, fee);
        }
        _safeTransfer(tokenOut, to, netOut);

        emit FeeTaken(tokenOut, msg.sender, treasury, fee, grossOut, netOut);

        // Best-effort: clear approval to reduce allowance exposure.
        _safeApproveExact(tokenIn, dexRouter, 0);

        if (amounts.length > 0) {
            amounts[amounts.length - 1] = netOut;
        }
        return amounts;
    }

    function _feeFromGross(uint256 grossOut) internal pure returns (uint256) {
        return (grossOut * uint256(FEE_BPS)) / uint256(BPS_DENOM);
    }

    function _safeApproveExact(address token, address spender, uint256 value) internal {
        // Many tokens require allowance to be zero before setting a new value.
        uint256 current = IERC20Like(token).allowance(address(this), spender);
        if (current != 0 && value != 0) {
            _callOptionalReturn(token, abi.encodeWithSelector(IERC20Like.approve.selector, spender, 0));
        }
        _callOptionalReturn(token, abi.encodeWithSelector(IERC20Like.approve.selector, spender, value));
    }

    function _safeTransfer(address token, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(IERC20Like.transfer.selector, to, value));
    }

    function _safeTransferFrom(address token, address from, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(IERC20Like.transferFrom.selector, from, to, value));
    }

    function _callOptionalReturn(address token, bytes memory data) internal {
        (bool success, bytes memory ret) = token.call(data);
        require(success, "ERC20_CALL_FAIL");
        if (ret.length > 0) {
            require(abi.decode(ret, (bool)), "ERC20_FALSE");
        }
    }
}

