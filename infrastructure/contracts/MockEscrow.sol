// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract MockEscrow {
    struct Deal {
        address maker;
        address taker;
        uint256 makerAmount;
        uint256 takerAmount;
        bool makerFunded;
        bool takerFunded;
        bool settled;
    }

    mapping(bytes32 => Deal) public deals;

    event DealOpened(bytes32 indexed dealId, address indexed maker, address indexed taker, uint256 makerAmount, uint256 takerAmount);
    event MakerFunded(bytes32 indexed dealId, address indexed maker);
    event TakerFunded(bytes32 indexed dealId, address indexed taker);
    event DealSettled(bytes32 indexed dealId);

    function openDeal(bytes32 dealId, address taker, uint256 makerAmount, uint256 takerAmount) external {
        Deal storage existing = deals[dealId];
        require(existing.maker == address(0), 'EXISTS');
        deals[dealId] = Deal({
            maker: msg.sender,
            taker: taker,
            makerAmount: makerAmount,
            takerAmount: takerAmount,
            makerFunded: false,
            takerFunded: false,
            settled: false
        });
        emit DealOpened(dealId, msg.sender, taker, makerAmount, takerAmount);
    }

    function fundMaker(bytes32 dealId) external {
        Deal storage deal = deals[dealId];
        require(deal.maker != address(0), 'MISSING');
        require(msg.sender == deal.maker, 'FORBIDDEN');
        require(!deal.settled, 'SETTLED');
        require(!deal.makerFunded, 'MAKER_ALREADY_FUNDED');
        deal.makerFunded = true;
        emit MakerFunded(dealId, msg.sender);
    }

    function fundTaker(bytes32 dealId) external {
        Deal storage deal = deals[dealId];
        require(deal.maker != address(0), 'MISSING');
        require(msg.sender == deal.taker, 'FORBIDDEN');
        require(!deal.settled, 'SETTLED');
        require(!deal.takerFunded, 'TAKER_ALREADY_FUNDED');
        deal.takerFunded = true;
        emit TakerFunded(dealId, msg.sender);
    }

    function settle(bytes32 dealId) external {
        Deal storage deal = deals[dealId];
        require(deal.maker != address(0), 'MISSING');
        require(!deal.settled, 'SETTLED');
        require(msg.sender == deal.maker || msg.sender == deal.taker, 'FORBIDDEN');
        require(deal.makerFunded && deal.takerFunded, 'NOT_READY');
        deal.settled = true;
        emit DealSettled(dealId);
    }
}
