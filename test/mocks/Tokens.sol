// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";

/// Like the testnet fUSD (plain ERC-20, 6 decimals, NO permit), but named "Demo USD" so it is never confused with fUSD.
contract FestUSDLike is ERC20 {
    constructor() ERC20("Demo USD (no permit)", "dUSD") {}

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// A standard EIP-2612 token (OpenZeppelin ERC20Permit), the kind most ERC-20s ship today.
contract PermitUSD is ERC20Permit {
    constructor() ERC20("Permit USD", "pUSD") ERC20Permit("Permit USD") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
