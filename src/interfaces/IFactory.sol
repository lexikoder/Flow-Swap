// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IFactory {
    // Get the address of the router
    function routerAddress() external view returns (address);

    // Get the pair address for two tokens
    function _pairAddress(address tokenA, address tokenB) external view returns (address);

    // Check if a pair exists for two tokens
    function _ispairexist(address tokenA, address tokenB) external view returns (bool);

    // Create a pair for two tokens
    function createPair(address tokenA, address tokenB) external;
    function setFee(uint _fee) external;
    function fee() external view returns (uint);
}