minhquanym

medium

# Attacker can burn ERC20 funds in the contract

## Summary
https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-protocol/src/BvbProtocol.sol#L450-L462

## Vulnerability Detail
Function `withdrawToken()` is used to receive the NFT manually after the contract is settled. However, an attacker can abuse this function to burn ERC20 funds in the contract.

The way it can be done is:
1. Attacker created and matched handcrafted orders with `collection` param equal to an ERC20 token address. 
2. Attacker call `withdrawToken()` with `tokenId` is the amount of funds he want to burn
3. `recipient` will be `address(0)` because order is not settled (cannot settle anyway)
4. It will transfer `tokenId` amount to `address(0)`, effectively burn these amount. 

## Impact
Loss of funds deposited into the contract.

I agreed that it will require that ERC20 token has to implement `safeTransferFrom()` function, which is quite weird so I put it as Medium

## Code Snippet
```solidity
function withdrawToken(bytes32 orderHash, uint tokenId) public {
    address collection = matchedOrders[uint(orderHash)].collection;

    address recipient = withdrawableCollectionTokenId[collection][tokenId];

    // Transfer NFT to recipient
    IERC721(collection).safeTransferFrom(address(this), recipient, tokenId); // @audit transfer to address 0 

    // This token is not withdrawable anymore
    withdrawableCollectionTokenId[collection][tokenId] = address(0);

    emit WithdrawnToken(orderHash, tokenId, recipient);
}
```

## Tool used

Manual Review

## Recommendation
Consider checking `address(0)` before transferring token.
