kirk-baird

high

# Reentrancy in `withdrawToken()` May Delete The Next User's Balance

## Summary

The function `withdrawToken()` does not have a reentrancy guard and calls an external contract. It is possible to reenter `settleContract()` to spend the same token that was just transferred out. If the `safeTransferFrom()` in `settleContract()` fails then the token balance is added to the bull. However, when `withdrawToken()` continues execution it will delete the balance of the bull.

## Vulnerability Detail

`withdrawToken()` makes a state change to `withdrawableCollectionTokenId[collection][tokenId]`  after it makes an external call to an ERC721 contract `safeTransferFrom()`. Since this external call will relinquish control to the `to` address which is `recipient`, the `recipient` smart contract may reenter `settleContract()`.

When calling `settleContract()` set the `tokenId` function parameter to the same one just transferred in `withdawToken()`. If transfer to the `bull` fails then the token is instead transferred to `BvbProtocol` and balance added to the bull, `withdrawableCollectionTokenId[order.collection][tokenId] = bull`

After `settleContract()` finishes executing control will revert back to `withdrawToken()` which then executes the line `withdrawableCollectionTokenId[collection][tokenId] = address(0)`. The balance of the bull is therefore delete for that token.

e.g. If we know a transfer will fail to a bull in a matched order we can a) create a fake order with ourselves b) reenter from `withdrawToken()` into `settleContract()` and therefore delete the bulls  `withdrawableCollectionTokenId` balance.
Steps:
- `BvpProtocol.matchOrder(orderA)` create a fake order (A)  with ones self
- `BvpProtocol.settleOrder(orderA)` settle the fake order (A) with ones self and ensure the ERC721 transfer from bull to bear fails.
- `BvpProtocol.matchOrder(orderB)` match the real order (B), this can be done at any time
- `BvbProtocol.withdrawToken(orderA, token1)`  the following setups happen during line #456
  - `ERC721(collection).safeTransferFrom(this, recipient, tokenId)` (`recipient` is bull from the fake order (A))
  - `recipient.onERC721Received()` called by `safeTransferFrom()` and gives execution control to `receipient`
  - `BvpProtocol.settleOrder(orderB, token1)` reenter to settle the real order using `token1` which does `withdrawableCollectionTokenId[order.collection][tokenId] = bull`
- Finish executing `BvbProtocol.withdrawToken(orderA, token1)`  after line #456 which does `withdrawableCollectionTokenId[collection][tokenId] = address(0)`
  
## Impact

If we know a transfer is going to fail to a `bull` for an ERC721 we can ensure the NFT is locked in the `BvbProtocol` contract. This NFT will be unrecoverable.

## Code Snippet
[withdrawToken()](https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-protocol/src/BvbProtocol.sol#L450-L462)
```solidity
    function withdrawToken(bytes32 orderHash, uint tokenId) public {
        address collection = matchedOrders[uint(orderHash)].collection;

        address recipient = withdrawableCollectionTokenId[collection][tokenId];

        // Transfer NFT to recipient
        IERC721(collection).safeTransferFrom(address(this), recipient, tokenId);

        // This token is not withdrawable anymore
        withdrawableCollectionTokenId[collection][tokenId] = address(0);
```

[settleContract()](https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-protocol/src/BvbProtocol.sol#L374-L411)
```solidity
    function settleContract(Order calldata order, uint tokenId) public nonReentrant {
        bytes32 orderHash = hashOrder(order);

        // ContractId
        uint contractId = uint(orderHash);

        address bear = bears[contractId];

        // Check that only the bear can settle the contract
        require(msg.sender == bear, "ONLY_BEAR");

        // Check that the contract is not expired
        require(block.timestamp < order.expiry, "EXPIRED_CONTRACT");

        // Check that the contract is not already settled
        require(!settledContracts[contractId], "SETTLED_CONTRACT");

        address bull = bulls[contractId];

        // Try to transfer the NFT to the bull (needed in case of a malicious bull that block transfers)
        try IERC721(order.collection).safeTransferFrom(bear, bull, tokenId) {}
        catch (bytes memory) {
            // Transfer NFT to BvbProtocol
            IERC721(order.collection).safeTransferFrom(bear, address(this), tokenId);
            // Store that the bull has to retrieve it
            withdrawableCollectionTokenId[order.collection][tokenId] = bull;
        }

        uint bearAssetAmount = order.premium + order.collateral;
        if (bearAssetAmount > 0) {
            // Transfer payment tokens to the Bear
            IERC20(order.asset).safeTransfer(bear, bearAssetAmount);
        }

        settledContracts[contractId] = true;

        emit SettledContract(orderHash, tokenId, order);
    }
```

## Tool used

Manual Review

## Recommendation

I recommend both of these solutions though either one will be sufficient on its own:
- Add `nonReentrant` modifier to `withdrawToken()`
- Set `withdrawableCollectionTokenId[collection][tokenId] = address(0)` before performing `IERC721(collection).safeTransferFrom(address(this), recipient, tokenId)` to apply the checks-effects-interactions pattern.
