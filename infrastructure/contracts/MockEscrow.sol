// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract MockEscrow {
    struct Deal {
        address maker;
        address taker;
        uint256 amount;
        bool settled;
    }

    mapping(bytes32 => Deal) public deals;

    event DealOpened(bytes32 indexed dealId, address indexed maker, address indexed taker, uint256 amount);
    event DealSettled(bytes32 indexed dealId);

    function openDeal(bytes32 dealId, address taker, uint256 amount) external {
        Deal storage existing = deals[dealId];
        require(existing.maker == address(0), 'EXISTS');
        deals[dealId] = Deal({maker: msg.sender, taker: taker, amount: amount, settled: false});
        emit DealOpened(dealId, msg.sender, taker, amount);
    }

    function settle(bytes32 dealId) external {
        Deal storage deal = deals[dealId];
        require(deal.maker != address(0), 'MISSING');
        require(!deal.settled, 'SETTLED');
        require(msg.sender == deal.maker || msg.sender == deal.taker, 'FORBIDDEN');
        deal.settled = true;
        emit DealSettled(dealId);
    }
}
