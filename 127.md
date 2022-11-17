GimelSec

high

# Attackers can use `reclaimContract()` to transfer assets in protocol to address(0)

## Summary

`reclaimContract()` would transfer payment tokens to `bulls[contractId]`. An attacker can make `reclaimContract()` transfer assets to address(0).

## Vulnerability Detail

An attacker can use a fake order to trick `reclaimContract()`. The fake order needs to meet the following requirements:
 
* `block.timestamp > order.expiry`. 
* `!settledContracts[contractId]`. 
* `!reclaimedContracts[contractId],`.

The first one is easy to fulfilled, an attacker can decide the content of the fake order. And the others are all satisfied since the fake order couldn’t be settled or reclaimed before.

Thus, `reclaimContract()` would run this line: `IERC20(order.asset).safeTransfer(bull, bullAssetAmount);`. `bull` is address(0) since `bulls[contractId]` hasn’t been filled. If `order.asset`’s implementation doesn’t make sure `to != address(0)`(e.g., https://github.com/ConsenSys/Tokens/blob/fdf687c69d998266a95f15216b1955a4965a0a6d/contracts/eip20/EIP20.sol). The asset would be sent to address(0).


```solidity
    function reclaimContract(Order calldata order) public nonReentrant {
        bytes32 orderHash = hashOrder(order);

        // ContractId
        uint contractId = uint(orderHash);

        address bull = bulls[contractId];

        // Check that the contract is expired
        require(block.timestamp > order.expiry, "NOT_EXPIRED_CONTRACT");

        // Check that the contract is not settled
        require(!settledContracts[contractId], "SETTLED_CONTRACT");

        // Check that the contract is not reclaimed
        require(!reclaimedContracts[contractId], "RECLAIMED_CONTRACT");

        uint bullAssetAmount = order.premium + order.collateral;
        if (bullAssetAmount > 0) {
            // Transfer payment tokens to the Bull
            IERC20(order.asset).safeTransfer(bull, bullAssetAmount);
        }

        reclaimedContracts[contractId] = true;

        emit ReclaimedContract(orderHash, order);
    }
```

## Impact

An attacker can use this vulnerability to transfer assets from BvB to address(0). It results in serious loss of funds.

## Code Snippet

https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-protocol/src/BvbProtocol.sol#L417-L443

## Tool used

Manual Review

## Recommendation

There are multiple solutions for this problem.

1. check `bulls[contractId] != address(0)`
2. check the order is matched `matchedOrders[contractId].maker != address(0)`
