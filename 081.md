ak1

medium

# Lack of choice for bull in picking the NFT

## Summary
During settlement of order, the bear will send any NFT based on what they wish.

This could not be fair. The bull will not have their choice of selection.

## Vulnerability Detail
[Oder ](https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-protocol/src/BvbProtocol.sol#L33-L44) struct any variable to represent the token ID.

[matchOrder](https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-protocol/src/BvbProtocol.sol#L306) is done without considering the token ID.

during [settleContract ](https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-protocol/src/BvbProtocol.sol#L374)the bear will transfer any token ID to bull from the collection of NFT.

## Impact
Lack of choice / selection for bull to pick their desired NFT.

## Code Snippet

https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-protocol/src/BvbProtocol.sol#L374-L411

## Tool used

Manual Review

## Recommendation
Add one more variable like `tokenID` to represent the bull's choice of NFT ID in the [Oder ](https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-protocol/src/BvbProtocol.sol#L33-L44)
