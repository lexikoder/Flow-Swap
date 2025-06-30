// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IPair {
    // Total share in the pool
    function totalShareInPool() external view returns (uint256);

    // Total balance of token A in the pool
    function tokenATotalBal() external view returns (uint256);

    // Total balance of token B in the pool
    function tokenBTotalBal() external view returns (uint256);

    function tokenA() external view returns (address);

    // Address of token B in the pair
    function tokenB() external view returns (address);

    function updateReserve(uint256 _amountTokenA, uint256 _amountTokenB) external;
    
    function mint(address _recipient, uint256 _amountTokenA, uint256 _amountTokenB) external;

    function burn(address _recipient, uint256 _sharemintAmount) external returns(uint,uint);
    function swap(
        address _recipient,
        address tokenIn,
        address tokenOut,
        uint amountTokenIn,
        uint amountTokenOut
    ) external returns(uint) ;
    // function burnEthPair(address _recipient, uint _sharemintAmount) external;
}