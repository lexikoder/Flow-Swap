// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./math.sol";


library liquidityMAth {
   
      
    function share(uint256 amountTokenA,uint256 amountTokenB, uint256 _totalTokenABal ,uint256 _totalShare) internal pure returns (uint256) {
        uint _amounttokenAB = amountTokenA * amountTokenB;
        if (_totalShare == 0){
           return math.sqrt(_amounttokenAB);
        }
        return (amountTokenA * _totalShare)/_totalTokenABal;
        
    }

    function removeLiquidityCalc(uint256 _sharesAmount,uint256 _totalShare ,uint256 _totalTokenABal,uint256 _totalTokenBBal) internal pure returns (uint256 ,uint256) {
        uint _amountTokenA = (_totalTokenABal * _sharesAmount)/_totalShare;
        uint  _amountTokenB = (_totalTokenBBal * _sharesAmount)/ _totalShare;
        return (_amountTokenA , _amountTokenB);
    }

    function addliquidityCalcTokenB(uint256 amountTokenA,uint256 _totalTokenABal,uint256 _totalTokenBBal)internal pure returns (uint256){
        uint  _amountTokenB = (_totalTokenBBal * amountTokenA)/ _totalTokenABal;
        return _amountTokenB;
    }

    function addliquidityCalcTokenA(uint256 amountTokenB,uint256 _totalTokenABal,uint256 _totalTokenBBal)internal pure returns (uint256){
        uint _amountTokenA = ( _totalTokenABal * amountTokenB  )/ _totalTokenBBal;
        return _amountTokenA;
    }
    // 10100000000000000000000
    // 29702970297029702970298
    // 10100

}