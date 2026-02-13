// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract MockFactory {
    mapping(bytes32 => address) public pairByKey;

    event PairRegistered(address indexed tokenA, address indexed tokenB, address pair);

    function registerPair(address tokenA, address tokenB, address pair) external {
        bytes32 key = _pairKey(tokenA, tokenB);
        pairByKey[key] = pair;
        emit PairRegistered(tokenA, tokenB, pair);
    }

    function getPair(address tokenA, address tokenB) external view returns (address) {
        return pairByKey[_pairKey(tokenA, tokenB)];
    }

    function _pairKey(address tokenA, address tokenB) private pure returns (bytes32) {
        return tokenA < tokenB ? keccak256(abi.encodePacked(tokenA, tokenB)) : keccak256(abi.encodePacked(tokenB, tokenA));
    }
}
