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
// 0xd4CC3080B8e56aA1dEBc2c8b194E0A96c959Adc2  link token
// 0x20A6C781a78101aeD87076E3E136Da532AD33381 AAVE
// 0xE64357309B2279A65eEaddaAdb4311aAE5CdbCa1 flowswap
// 0xe3695D36bDb75b6f6EbE637F3f83d2a53bdA661a Sushiswap
// 0x1E98042187c8Ce77Fe18957b14123B30EFe9CC3B  Uniswap
// 0xfd08b9B43bC7Ed6c699F07b487e00E3662c5fFB3 wrapped btc
// 0x9683ddB6FCdf80F847303ECFEDa2a7B88F7F5f0d weth

// 0x4Bb463407889Dcac3Bc9C96C8c24f5ce575aF480  factory
// 0x3a45175B6dF92B7ECd949301d09Ff7a5C8A58a46  router

//  new address
// 0x37880DeAF8D1d9B09605Dd831F0607Ab053d0446 aave
// 0x0BDbDC521f2B3fC3642D74F007c2F38a6dE2C3fE flowswap
// 0x510DabcE13beF21607eE9166800d984ADCbE9a56 uni
// 0xDb344bae9EC5106C8af663719df8BD2eeE59440B wbtc
// 0x189E70F8A3C4142d03263c0C1a26E63986a65376 Sushiswap
