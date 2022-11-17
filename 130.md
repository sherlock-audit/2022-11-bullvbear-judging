GimelSec

medium

# It doesn't handle fee-on-transfer/deflationary tokens

## Summary

The protocol doesn't handle fee-on-transfer/deflationary tokens, users will be unable to call `settleContract` and `reclaimContract` due to not enough assets in the contract.
Though the protocol uses `allowedAsset` to set the asset as supported as payment, we can't guarantee that the allowed non-deflationary token will always not become a deflationary token, especially upgradeable tokens (for example, USDC).

## Vulnerability Detail

Assume that A token is a deflationary token, and it will take 50% fee when transferring tokens. And the protocol only set 4% fee.

If a user is bear and call `mathOrder` with `order.premium = 100`, the `takerPrice` will be `100 + 100*4% = 104` but the protocol will only get `104 * 50% = 52` tokens in [L354](https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-protocol/src/BvbProtocol.sol#L354). 
Same problem in `order.collateral`, the user will be unable to call `settleContract` because the contract doesn't have enough A tokens.

## Impact

The protocol will be unable to pay enough tokens to users when users want to call `settleContract` or `reclaimContract`.

## Code Snippet

https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-protocol/src/BvbProtocol.sol#L354
https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-protocol/src/BvbProtocol.sol#L358

## Tool used

Manual Review

## Recommendation

Use `balanceAfter - balanceBefore`:

```solidity
    uint256 balanceBefore = deflationaryToken.balanceOf(address(this));
    deflationaryToken.safeTransferFrom(msg.sender, address(this), takerPrice);
    uint256 balanceAfter = deflationaryToken.balanceOf(address(this));
    premium = (balanceAfter - balanceBefore) - bearFees;
```
