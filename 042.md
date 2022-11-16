dic0de

high

# Malicious Users can create a fake `SellOrder` and steal from other users.

## Summary
When matching orders via the `matchOrder` function, the contract does not assert that either the `order.collateral` or `order.premium` amounts are greater than zero `0` this is left to the prerogative of the users. Moreover, the contract allows the `order.maker` to be the same as the `order.taker`. As such, a user can make an order and be the one to `matchOrder` in the contract. With this, it is easy for a user to make an order that requires `0` collateral, be the same person that matches the order equivalently becoming the taker, then create a `sellOrder` where other users can buy the malicious `sellOrder`. When the victims settle their contracts via the `settleContract ()` functions using the malicious bought `sellOrder` they will only receive the `order.premium`
## Vulnerability Detail
A malicious user can create an `order` with `0` collateral. Thereafter, match the same order via the `matchOrder ()` function https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-protocol/src/BvbProtocol.sol#L306. With this the user will become both the Taker and the Maker of the contract position. The following test case shows that it is possible to deposit 0 collateral as well as the Maker of the Order can be the same as the Taker of the contract position.  
```solidity
function testMatchSeveralOrders() public {
        BvbProtocol.Order memory order = defaultOrder();
        bytes32 orderHash = bvb.hashOrder(order);

        BvbProtocol.Order memory secondOrder = defaultOrder();
        secondOrder.isBull = false;
        bytes32 secondOrderHash = bvb.hashOrder(secondOrder);

        bytes memory signature = signOrder(bullPrivateKey, order);
        bytes memory secondSignature = signOrder(bullPrivateKey, secondOrder);

        BvbProtocol.Order[] memory orders = new BvbProtocol.Order[](2);
        orders[0] = order;
        assertEq(order.collateral, 0, "Assert order collateral is 0");
        orders[1] = secondOrder;
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = signature;
        signatures[1] = secondSignature;
        vm.prank(bull);

        bvb.batchMatchOrders(orders, signatures);

        assertEq(bvb.bulls(uint(orderHash)), bull, "Bvb correctly saved the bull for the first order");
        assertEq(bvb.bears(uint(orderHash)), bull, "Bvb correctly saved the bear for the first order");
```
The test case passed successfully which shows that the Maker is the same as the Taker and the `order.collateral` is 0. 
## Impact
1. A Malicious user can create a malicious `sellOrder` that lacks collateral and whenever victims buy such contract positions and use it to settle their contract positions, they will lose their NFTs. 
## Code Snippet
https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-protocol/src/BvbProtocol.sol#L306
## Tool used

Manual Review

## Recommendation
