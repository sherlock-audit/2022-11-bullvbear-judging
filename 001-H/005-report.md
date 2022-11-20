obront

medium

# Can use invalid signatures from address(0) to create and sell fake positions

## Summary

`ECDSA.recover` returns `address(0)` for invalid signatures. Since there is no check for this, anyone is able to create orders with `address(0)` as the maker.

## Vulnerability Detail

The core of this bug comes from the fact that `ECDSA.recover()` will return `address(0)` for invalid signatures. As a result we can make `isValidSignature()` pass with `signer == address(0)`.

Fortunately, there are no ways to steal user or protocol funds from this issue. But there are some actions that would be harmful and confusing to users. Here is a simple example...

1) Create an order with `maker == address(0)`, `isBull == true`, and `collateral == 0`.
2) When a user accepts this, since the order `isBull`, the bull will be set as `address(0)`, and since the collateral is set to zero, `makerPrice == 0`. This will avoid transferring any assets from that address, so the function will go through.
3) However, the exact same order can be matched by another user, because `require(bulls[uint(orderHash)] == address(0), "ORDER_ALREADY_MATCHED");` will pass.
4) This could cause unpredicted behavior, where orders are overwritten and disappear.

This can become more confusing because we can then turn around and sell this order on behalf of `address(0)`, since the bogus signature will also be valid for sell orders.

Although it is a major problem to allow signatures on behalf of another account, since there is no direct risk to user funds (that I can see), I am submitting this as a Medium.

## Impact

Users can create or sell orders on behalf of the zero address, which can lead to overwritten orders.

## Code Snippet

https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-protocol/src/BvbProtocol.sol#L699-L701

https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-protocol/src/BvbProtocol.sol#L734-L761

## Tool used

Manual Review

## Recommendation

Add in a check to ensure that the signer is not the zero address when validating the signature:

```diff
function isValidSignature(address signer, bytes32 orderHash, bytes calldata signature) public pure returns (bool) {
+   require(signer != address(0));
    return ECDSA.recover(orderHash, signature) == signer;
}
```