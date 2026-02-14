// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20Like {
    function transferFrom(address from, address to, uint256 value) external returns (bool);
    function transfer(address to, uint256 value) external returns (bool);
}

contract MockRouter {
    event SwapExecuted(bytes32 indexed executionRef, address indexed sender, address indexed recipient, uint256 amountIn, uint256 amountOut);

    // Price of 1 WETH in USDC, scaled by 1e18 (USDC uses 18 decimals in this mock environment).
    uint256 public ethUsdPriceE18;
    address public immutable owner;
    address public tokenWeth;
    address public tokenUsdc;

    event EthUsdPriceUpdated(uint256 previousPriceE18, uint256 nextPriceE18);
    event TokenPairConfigured(address weth, address usdc);

    constructor() {
        owner = msg.sender;
        // Default 2000 USD per ETH. Can be updated by deploy script or operator.
        ethUsdPriceE18 = 2000e18;
        tokenWeth = address(0);
        tokenUsdc = address(0);
    }

    function setEthUsdPriceE18(uint256 nextPriceE18) external {
        require(msg.sender == owner, 'OWNER');
        require(nextPriceE18 > 0, 'PRICE');
        uint256 prev = ethUsdPriceE18;
        ethUsdPriceE18 = nextPriceE18;
        emit EthUsdPriceUpdated(prev, nextPriceE18);
    }

    function setTokenPair(address weth, address usdc) external {
        require(msg.sender == owner, 'OWNER');
        require(weth != address(0) && usdc != address(0), 'ZERO');
        tokenWeth = weth;
        tokenUsdc = usdc;
        emit TokenPairConfigured(weth, usdc);
    }

    function getAmountsOut(uint256 amountIn, address[] calldata path) external view returns (uint256[] memory amounts) {
        require(path.length >= 2, 'PATH');
        address tokenIn = path[0];
        address tokenOut = path[path.length - 1];
        uint256 amountOut = _amountOut(amountIn, tokenIn, tokenOut);
        amounts = new uint256[](2);
        amounts[0] = amountIn;
        amounts[1] = amountOut;
        return amounts;
    }

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

        uint256 amountOut = _amountOut(amountIn, tokenIn, tokenOut);
        require(amountOut >= amountOutMin, 'SLIPPAGE');
        require(IERC20Like(tokenOut).transfer(to, amountOut), 'TRANSFER_OUT');

        bytes32 executionRef = keccak256(abi.encodePacked(msg.sender, to, tokenIn, tokenOut, amountIn, block.number));
        emit SwapExecuted(executionRef, msg.sender, to, amountIn, amountOut);

        amounts = new uint256[](2);
        amounts[0] = amountIn;
        amounts[1] = amountOut;
        return amounts;
    }

    function _amountOut(uint256 amountIn, address tokenIn, address tokenOut) internal view returns (uint256) {
        // For WETH/USDC quoting and swaps, apply ethUsdPriceE18.
        // For any other pair, behave like a 1:1 swap (used by some tests / demo paths).
        uint256 price = ethUsdPriceE18;
        if (price == 0) {
            return amountIn;
        }

        // Prefer configured mock token addresses (Slice 21). If not configured, fall back to canonical Base addresses
        // for legacy deployments.

        if (tokenIn == tokenOut) {
            return amountIn;
        }

        // NOTE: since both tokens use 18 decimals in this repo's mock ERC20, we can use a direct 1e18 scale.
        // If callers use a 6-decimal USDC, this will not be accurate; that is out of scope for the mock DEX fork.
        //
        // amountOut( WETH->USDC ) = amountIn * price / 1e18
        // amountOut( USDC->WETH ) = amountIn * 1e18 / price
        //
        // For pairs other than WETH/USDC, default to 1:1.
        //
        // We detect direction by comparing symbols in the client path, not here; for simplicity, treat "WETH-ish"
        // and "USDC-ish" by checking against well-known canonical addresses.
        address WETH_ADDR = tokenWeth;
        address USDC_ADDR = tokenUsdc;
        if (WETH_ADDR == address(0) || USDC_ADDR == address(0)) {
            WETH_ADDR = 0x4200000000000000000000000000000000000006;
            USDC_ADDR = 0x036CbD53842c5426634e7929541eC2318f3dCF7e;
        }

        bool inIsWeth = tokenIn == WETH_ADDR;
        bool outIsUsdc = tokenOut == USDC_ADDR;
        bool inIsUsdc = tokenIn == USDC_ADDR;
        bool outIsWeth = tokenOut == WETH_ADDR;

        if (inIsWeth && outIsUsdc) {
            return (amountIn * price) / 1e18;
        }
        if (inIsUsdc && outIsWeth) {
            return (amountIn * 1e18) / price;
        }
        return amountIn;
    }
}
