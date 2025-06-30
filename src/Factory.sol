// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/proxy/Clones.sol"; 
import "@openzeppelin/contracts/access/Ownable.sol"; 
import "./Pair.sol";
import "./interfaces/Itoken.sol";  

contract Factory is Ownable {

    address pairImplementationReference;
    address public routerAddress;
    mapping(address => mapping(address => address)) public _pairAddress;
    mapping(address => mapping(address => bool)) public _ispairexist;
    mapping (address => bool ) public checkpair;

    uint public fee;
    address public feeAddress;
    address WETH;

    // pair event to emmit
    
    constructor(address _initialOwner,address weth) Ownable(_initialOwner) {
        
        pairImplementationReference = address(new Pair());
        WETH = weth;
    }

    function createPair(address tokenA, address tokenB) public {
        require(routerAddress != address(0),"router address not set");
        require(_pairAddress[tokenA][tokenB] == address(0));
        require(_pairAddress[tokenB][tokenA] == address(0));
        string memory pairSymbol = concatenateWithSeparator(Itoken(tokenA).symbol(),Itoken(tokenB).symbol());
        address newPairAddress = Clones.clone(pairImplementationReference);
        Pair _pair = Pair(newPairAddress);
        _pair.initialize(routerAddress,tokenA,tokenB,WETH,pairSymbol);
        _pairAddress[tokenA][tokenB] = newPairAddress;
        _pairAddress[tokenB][tokenA] = newPairAddress;
        _ispairexist[tokenA][tokenB] = true;
        _ispairexist[tokenB][tokenA] = true;
        checkpair[newPairAddress]=true;
 
    //   Emit event
        
    }

    function setRouter(address _routerAddress) public onlyOwner{
       routerAddress = _routerAddress;
    } 

    function setFee(uint _fee) public onlyOwner{
       fee = _fee;
    }

    function setFeeAddress(address _feeadress) public onlyOwner{
       feeAddress = _feeadress;
    }

     function concatenateWithSeparator(string memory str1, string memory str2) public pure returns (string memory) {
        string memory result = string(abi.encodePacked("flowswap","-",str1,"-",str2));
        return result; 
    }
     
     
    
}