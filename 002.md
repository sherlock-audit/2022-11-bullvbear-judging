obront

high

# batchMatchOrders can be abused to underpay takerPrice

## Summary

The `batchMatchOrders()` function allows a user to become the taker on multiple orders at once. Because the `matchOrder()` function accepts payments via `msg.value`, this can be abused to pay once to become the taker on an arbitrary number of orders (as long as they all have the same takerPrice and accept WETH).

## Vulnerability Detail

In `batchMatchOrders()`, a user submits a list of orders and signatures, and the user becomes the taker on each of these orders. 

```solidity
function batchMatchOrders(Order[] calldata orders, bytes[] calldata signatures) external returns (uint[] memory) {
    require(orders.length == signatures.length, "INVALID_ORDERS_COUNT");

    uint[] memory contractIds = new uint[](orders.length);

    for (uint i; i<orders.length; i++) {
        contractIds[i] = matchOrder(orders[i], signatures[i]);
    }

    return contractIds;
}
```
Within the `matchOrder()` function, the order is validated and fees are calculated. Then the taker is expected to deposit collateral or premium (depending on whether they are the bull or bear).

They are able to make this payment either by sending Ether along with their transaction, or by the usual ERC20 transfer. 

However, if a user sends Ether, their `msg.value` will be used for all iterations of the batch loop.

```solidity
if (msg.value > 0) {
    require(msg.value == takerPrice, "INVALID_ETH_VALUE");
    require(order.asset == weth, "INCOMPATIBLE_ASSET_ETH_VALUE");

    WETH(weth).deposit{value: msg.value}();
}
```
Here is a small example of how this might be abused:
- There are 3 pending orders with a maker on the bear side that have a collateral price of 10 WETH to take the bull side (including fees, for the simplicity of the example)
- A malicious user calls batchMatchOrders with all 3 orders, and a `msg.value` of 10 ether
- For each order, the protocol confirms that `msg.value == takerPrice` and marks the user as the bull
- If the NFT price falls below 10 ether, the bears will each send free NFTs to our hacker; otherwise, they will be able to withdraw 10 ether plus premiums from each order, netting a profit of 20+ ether

## Impact

A malicious user can underpay for their side of a trade, collecting unearned revenue from the protocol.

## Code Snippet

https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-protocol/src/BvbProtocol.sol#L546-L556

https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-protocol/src/BvbProtocol.sol#L348-L353

## Tool used

Manual Review

## Recommendation

If you don't want to remove batch matched orders or payments via msg.value, you'll need to check in `batchMatchOrders()` that msg.value equals 0 or the total across the orders, and then refactor `matchOrder()` to allow msg.value to be greater than takerPrice.