pashov

high

# Using a vulnerable ECDSA library can result in signature malleability

## Summary
The codebase is using a vulnerable version of ECDSA, making it susceptible to signature malleability attacks

## Vulnerability Detail
The repository uses a OZ library version of 4.7.0, but OpenZeppelin have announced versions >= 4.1.0 up to < 4.7.3 of their library are susceptible to [ECDSA signature malleability](https://github.com/OpenZeppelin/openzeppelin-contracts/security/advisories/GHSA-4h98-2769-gh6h). The problem is that `ECDSA.recover()` is vulnerable to a kind of signature malleability due to accepting EIP-2098 compact signatures in addition to the traditional 65 byte signature format.
Now if the `matchOrder()` function was called with a signature that has been used, but since it is malleable now almost the same order is reused, now if the `makerPrice > 0` the the `order.maker` can lose more assets than he wanted because of 
```jsx
if (makerPrice > 0) {
            IERC20(order.asset).safeTransferFrom(order.maker, address(this), makerPrice);
        }
```

## Impact
If signature malleability is exploited, the maker of an order can lose more assets than what was the `makerPrice` set. Since this is a loss of funds I think High severity is appropriate.

## Code Snippet
https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-protocol/src/BvbProtocol.sol#L700
## Tool used

Manual Review

## Recommendation
Upgrade OpenZeppelin library to latest version or at least to version 4.7.3