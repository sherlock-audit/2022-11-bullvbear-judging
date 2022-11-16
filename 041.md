dic0de

medium

# Unbounded iterations might make it impossible to buy position

## Summary
The contract allows users to buy position such that one can buy a `sellOrder` position via `buyPosition ()` function as shown here https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-protocol/src/BvbProtocol.sol#L470. The `SellOrder` struct has an array of whitelisted addresses that are permitted to use the `SellOrder` defined by the maker of the `sellOrder` as shown here https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-protocol/src/BvbProtocol.sol#L58-L68. There is no limit set to the number of whitelisted addresses which forms part of the `SellOrder` . If the number of addresses in this array is a lot, it might make it impossible for some buyers of the position to buy the position. 
## Vulnerability Detail
The `buyPosition ()` function is used to buy `SellOrders` . These are orders where contract position owners would wish to sell their position. As such, contract position owners, would create a `SellOrder` with a list of whitelisted addresses that are allowed to buy the position. 
The buyer of the position, would call the function `buyPosition ()` to buy the `SellOrder`. The contract then checks if the `SellOrder` is valid and as well checks if the `msg.sender` is a whitelisted buyer of the position as seen here; https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-protocol/src/BvbProtocol.sol#L488. 
When the `isWhitelisted` function is called,  it runs the array of the whitelisted addresses against the buyer address to check if they are allowed to buy the position or not https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-protocol/src/BvbProtocol.sol#L719-L728
If the array of the `whitelisted` addresses is long enough, then the function might run our of gas making it impossible for the buyer to buy the position. 
## Impact
1. Some buyers might not be able to buy a `SellOrder` position. 
2. The `SellOrder` position might not be settled. 
## Code Snippet
1. https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-protocol/src/BvbProtocol.sol#L470.
2. https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-protocol/src/BvbProtocol.sol#L58-L68.
3. https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-protocol/src/BvbProtocol.sol#L488. 
## Tool used

Manual Review

## Recommendation
1. Consider setting a limit to the `isWhitelisted ()` function to ensure the function does not run out of gas. 
2. Because creating the `SellOrder` is done offchain and not part of this review, then maybe the team can ensure that there is a limit to the number of whitelisted addresses when created the `SellOrder`