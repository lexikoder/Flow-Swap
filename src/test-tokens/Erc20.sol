// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Import OpenZeppelin's ERC20 implementation
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract MyToken is ERC20 {

    constructor(
        string memory name,
        string memory symbol,
        uint256 initialSupply
    ) ERC20(name, symbol) {
        _mint(msg.sender, initialSupply * (10 ** decimals())); // Mint the initial supply to the contract owner
    }

    // Function to mint new tokens (restricted to the owner)
    function mint(address to, uint256 amount) external  {
        _mint(to, amount);
    }

    // Function to burn tokens from a holder
    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }
}
