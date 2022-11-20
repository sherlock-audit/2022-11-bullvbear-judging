WATCHPUG

high

# Bull can `transferPosition()` to `address(0)` and the original order can be matched again

## Summary

Using `bulls[uint(orderHash)] == address(0)` to check whether the order is matched is insufficient, the bull can `transferPosition` to `address(0)` and the order can be matched again.

## Vulnerability Detail

An order must not be matched more than once.

There is a check presented in the current implementation to prevent that: L760 `require(bulls[uint(orderHash)] == address(0), "ORDER_ALREADY_MATCHED");`.

However, this check can be easily bypassed by the bull, as they can `transferPosition()` to `address(0)` anytime.

Then the original order can be matched again.

## Impact

Attacker can match the orders by bear makers multiple times, pulling `order.premium + bearFees` from the victims' wallet as many times as they want.

## Code Snippet

https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-protocol/src/BvbProtocol.sol#L734-L761

https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-protocol/src/BvbProtocol.sol#L521-L538

## Tool used

Manual Review

## Recommendation

Consider using `matchedOrders[contractId]` to check if the order has been matched or not. Also, consider disallowing `transferPosition()` to `address(0)`.