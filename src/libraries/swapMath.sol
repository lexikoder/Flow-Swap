// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library swapMAth {
   uint constant precision = 1000;

   function swapToTokenB(uint _amountTokenA,uint _totaltokenABal,uint _totaltokenBBal,uint fee)internal pure returns(uint) {
     uint numerator =  _amountTokenA * (1000 - ((fee * precision)/1000)) * _totaltokenBBal;
     uint denominator = (1000 * _totaltokenABal) + (_amountTokenA * (1000 - ((fee * precision)/1000)));
     return   numerator / denominator;
   } 

   function swapToTokenA(uint _amountTokenB,uint _totaltokenABal,uint _totaltokenBBal,uint fee)internal pure returns(uint) {
     uint numerator  = _amountTokenB * _totaltokenABal * precision;
     uint denominator  = ((1000 - ((fee * precision)/1000)) * _totaltokenBBal) - (_amountTokenB * ((1000 - (fee * precision)/1000)));
     return  numerator / denominator;
   } 
}
