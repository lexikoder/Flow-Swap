// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "./interfaces/IWETH.sol";
import "./interfaces/IFactory.sol";
import "./libraries/liquidityMath.sol";
import "./libraries/swapMath.sol";
import "./interfaces/IPair.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract Router is ReentrancyGuardUpgradeable  {
    using SafeERC20 for IERC20;
    address public WETH;
    address public factory;
    

    constructor(address _weth,address _factory) {
       WETH = _weth;
       factory= _factory;
    }
     
    modifier validAddress(
        address _address
    ) {
        require(_address != address(0), "address zero not allowed");
        _;
    }

    modifier validAmount(
        uint256 _amount
    ) {
        require(_amount > 0, "amount zero not allowed");
        _;
    }

    modifier validAmountTokenAB(
        uint256 _amountTokenA,uint256 _amountTokenB
    ) {
        require(_amountTokenA > 0 && _amountTokenB > 0 , "amount zero not allowed");
        _;
    }

    modifier beforeDeadline(uint _deadline) {
        require(block.timestamp <= _deadline, "Deadline has passed");
        _;
    }


    function addLiquidity(address tokenA, address tokenB , uint _amountTokenA,uint _amountTokenB, uint _deadline )public  beforeDeadline(_deadline) nonReentrant{ 
          require(_amountTokenA > 0 && _amountTokenB > 0 , "amount zero not allowed");
          address  pairAddress = IFactory(factory)._pairAddress(tokenA,tokenB);
          require (pairAddress != address(0),"Pair not deployed");

          uint tokenAtotalBal = IPair(pairAddress).tokenATotalBal();
          uint tokenBtotalBal = IPair(pairAddress).tokenBTotalBal();
          if (tokenAtotalBal ==0 && tokenBtotalBal == 0){
          
          IERC20(tokenA).safeTransferFrom(msg.sender, pairAddress, _amountTokenA);
          IERC20(tokenB).safeTransferFrom(msg.sender, pairAddress, _amountTokenB);
          
          }else{
          uint amountTokenB = liquidityMAth.addliquidityCalcTokenB(_amountTokenA,tokenAtotalBal,tokenBtotalBal);
          IERC20(tokenA).safeTransferFrom(msg.sender, pairAddress, _amountTokenA);
          IERC20(tokenB).safeTransferFrom(msg.sender, pairAddress, amountTokenB);
          require (amountTokenB == _amountTokenB,"Incorrect liquidity amount");
          }
        //   uint amountTokenA = liquidityMAth.addliquidityCalcTokenA(amountTokenB,tokenAtotalBal,tokenBtotalBal);
          
          IPair(pairAddress).updateReserve(_amountTokenA,_amountTokenB);
          IPair(pairAddress).mint(msg.sender,_amountTokenA,_amountTokenB);
    } 

    function removeLiquidity(address pairAddress,uint _sharemintAmount,uint _deadline)public validAddress(pairAddress) validAmount(_sharemintAmount) beforeDeadline(_deadline) nonReentrant{
        IPair(pairAddress).burn(msg.sender,_sharemintAmount);
       
    } 

    function addLiquidityEThPair( address tokenB,uint _amountTokenB, uint _deadline)public payable beforeDeadline(_deadline) nonReentrant{
          _wrap();
          require(msg.value > 0 && _amountTokenB > 0 , "amount zero not allowed");
          address  pairAddress = IFactory(factory)._pairAddress(WETH,tokenB);
          require (pairAddress != address(0),"Pair not deployed");
          
          uint tokenAtotalBal = IPair(pairAddress).tokenATotalBal();
          uint tokenBtotalBal = IPair(pairAddress).tokenBTotalBal();
          if (tokenAtotalBal ==0 && tokenBtotalBal == 0){
              IERC20(WETH).safeTransferFrom(address(this), pairAddress, msg.value);
          IERC20(tokenB).safeTransferFrom(msg.sender, pairAddress, _amountTokenB);
          }else{
          uint amountTokenB = liquidityMAth.addliquidityCalcTokenB(msg.value,tokenAtotalBal,tokenBtotalBal);
        //   uint amountTokenA = liquidityMAth.addliquidityCalcTokenA(amountTokenB,tokenAtotalBal,tokenBtotalBal);
          IERC20(WETH).safeTransferFrom(address(this), pairAddress, msg.value);
          IERC20(tokenB).safeTransferFrom(msg.sender, pairAddress, amountTokenB);
          require (amountTokenB == _amountTokenB,"Incorrect liquidity amount");
          }
          
          IPair(pairAddress).updateReserve(msg.value,_amountTokenB);
          IPair(pairAddress).mint(msg.sender,msg.value,_amountTokenB);
    } 

    function removeLiquidityEThPair(address pairAddress,uint _sharemintAmount,uint _deadline)public validAddress(pairAddress) validAmount(_sharemintAmount) beforeDeadline(_deadline) nonReentrant {
        (uint amountTokenA, ) =IPair(pairAddress).burn(msg.sender,_sharemintAmount);
        _unwrap(amountTokenA);
        (bool success, ) = msg.sender.call{value: amountTokenA}(""); // Safely transfer Ether
         require(success, "Transfer failed");
        
     
    } 

    function swapTokenForToken(address tokenIn,address tokenOut,uint amountTokenIn,uint amountTokenOut,uint _deadline)public validAmountTokenAB(amountTokenIn,amountTokenOut) beforeDeadline(_deadline)  nonReentrant{
        require(tokenIn != address(0) && tokenOut != address(0),"address zero not allowed");
        
        address  pairAddress = IFactory(factory)._pairAddress(tokenIn,tokenOut);
      
        IERC20(tokenIn).safeTransferFrom(msg.sender, pairAddress, amountTokenIn);
        
        IPair(pairAddress).swap(msg.sender,tokenIn,tokenOut,amountTokenIn,amountTokenOut);
        
       
    }
    
    
    function swapTokenForEth(address tokenIn,uint amountTokenIn,uint amountTokenOut,uint _deadline)public  beforeDeadline(_deadline){
        require(tokenIn != address(0) ,"address zero not allowed");
        address  pairAddress = IFactory(factory)._pairAddress(tokenIn,WETH);
        (uint _amountTokenOut) = IPair(pairAddress).swap(msg.sender,tokenIn,WETH,amountTokenIn,amountTokenOut);
        _unwrap(_amountTokenOut);
        IERC20(tokenIn).safeTransferFrom(msg.sender, pairAddress, amountTokenIn);
        (bool success, ) = msg.sender.call{value: _amountTokenOut}(""); // Safely transfer Ether
        require(success, "Transfer failed");
        
    }
    function swapEthForToken(address tokenOut,uint amountTokenOut,uint _deadline)public payable  beforeDeadline(_deadline){
        _wrap();
        require(tokenOut != address(0),"address zero not allowed");
        address  pairAddress = IFactory(factory)._pairAddress(WETH,tokenOut);
        IPair(pairAddress).swap(msg.sender,WETH,tokenOut,msg.value,amountTokenOut);

    }

    function _wrap() private {
        require(msg.value > 0, "2001");
        IWETH(WETH).deposit{ value: msg.value }();
    }

    
    function _unwrap(
        uint256 _amount
    ) private  validAmount(_amount) {
        IWETH(WETH).withdraw(_amount);
    }
    
    function amountLiquidityB(address tokenA, address tokenB, uint _tokenAmountA)public view returns(uint){
       address  pairAddress = IFactory(factory)._pairAddress(tokenA,tokenB);
       uint tokenAtotalBal = IPair(pairAddress).tokenATotalBal();
       uint tokenBtotalBal = IPair(pairAddress).tokenBTotalBal();
       uint amountTokenB = liquidityMAth.addliquidityCalcTokenB(_tokenAmountA,tokenAtotalBal,tokenBtotalBal);
       return amountTokenB;
    }

    function amountLiquidityBEth( address tokenB, uint _tokenAmountA)public view returns(uint){
        address  pairAddress = IFactory(factory)._pairAddress(WETH,tokenB);
        uint tokenAtotalBal = IPair(pairAddress).tokenATotalBal();
          uint tokenBtotalBal = IPair(pairAddress).tokenBTotalBal();
       uint amountTokenB = liquidityMAth.addliquidityCalcTokenB(_tokenAmountA,tokenAtotalBal,tokenBtotalBal);
       return amountTokenB;
    }

    function amountOftokenOut(address tokenIn,address tokenOut,uint amountTokenIn)public view returns(uint) {
        address  pairAddress = IFactory(factory)._pairAddress(tokenIn,tokenOut);
        address tokenA = IPair(pairAddress).tokenA(); 
        
       
        uint tokenAtotalBal = IPair(pairAddress).tokenATotalBal();
        uint tokenBtotalBal = IPair(pairAddress).tokenBTotalBal();
       
        uint tokenAmountOut;
        uint fee = IFactory(factory).fee();
        
        if (tokenA == tokenIn){
          tokenAmountOut =  swapMAth.swapToTokenB(amountTokenIn,tokenAtotalBal,tokenBtotalBal,fee);
        }else{
            tokenAmountOut =  swapMAth.swapToTokenB(amountTokenIn,tokenBtotalBal, tokenAtotalBal,fee);
        }
           
        
        return  tokenAmountOut;
    }
    
    


    receive() external payable {
    
    }
      
}