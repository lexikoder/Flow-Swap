// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "./libraries/liquidityMath.sol";
import "./libraries/swapMath.sol";
import "./interfaces/IFactory.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "./interfaces/IWETH.sol";

contract Pair is ERC20Upgradeable {
    using SafeERC20 for IERC20;
    uint256 totalShareInPool;
    uint256 public tokenATotalBal;
    uint256 public tokenBTotalBal;
    address Router;
    address public tokenA;
    address public tokenB;
    address public factory;
    address public WETH;

    constructor() {
        _disableInitializers();
    }

    // Modifier to restrict access to only the owner
    modifier onlyRouter() {
        require(msg.sender == Router, "only router can call this contract");
        _;
    }
    modifier validAmount(uint256 _amount) {
        require(_amount > 0, "amount zero not allowed");
        _;
    }

    function initialize(
        address _router,
        address _tokenA,
        address _tokenB,
        address _weth,
        string memory pairsymbol
    ) external initializer {
        __ERC20_init("flowswap-pair", pairsymbol);
        __Router_init(_router);
        tokenA = _tokenA;
        tokenB = _tokenB;
        factory = msg.sender;
        WETH = _weth;
    }

    function swap(
        address _recipient,
        address tokenIn,
        address tokenOut,
        uint amountTokenIn,
        uint amountTokenOut
    ) external onlyRouter returns (uint) {
        uint fee = IFactory(factory).fee();
        uint tokenAmountOut;

        if (tokenIn == tokenA) {
            tokenAmountOut = swapMAth.swapToTokenB(
                amountTokenIn,
                tokenATotalBal,
                tokenBTotalBal,
                fee
            );
            tokenATotalBal += amountTokenIn;
            tokenBTotalBal -= tokenAmountOut;
        } else {
            tokenAmountOut = swapMAth.swapToTokenB(
                amountTokenIn,
                tokenBTotalBal,
                tokenATotalBal,
                fee
            );
            tokenBTotalBal += amountTokenIn;
            tokenATotalBal -= tokenAmountOut;
        }

        uint balBefore;
        uint balafter;
        if (tokenOut == WETH) {
            balBefore = IERC20(tokenOut).balanceOf(Router);
            IERC20(tokenOut).safeTransfer(Router, tokenAmountOut);
            balafter = IERC20(tokenOut).balanceOf(Router);
        } else {
            balBefore = IERC20(tokenOut).balanceOf(_recipient);
            IERC20(tokenOut).safeTransfer(_recipient, tokenAmountOut);
            balafter = IERC20(tokenOut).balanceOf(_recipient);
        }

        uint diff = balafter - balBefore;
        // implementing slipage
        require(diff >= amountTokenOut, "low token recieved");
        return (tokenAmountOut);
    }

    function mint(
        address _recipient,
        uint _amountTokenA,
        uint _amountTokenB
    ) external onlyRouter {
        uint sharemintAmount = liquidityMAth.share(
            _amountTokenA,
            _amountTokenB,
            tokenATotalBal,
            totalShareInPool
        );
        totalShareInPool += sharemintAmount;
        _mint(_recipient, sharemintAmount);
    }

    function burn(
        address _recipient,
        uint _sharemintAmount
    ) external onlyRouter returns (uint, uint) {
        require(balanceOf(_recipient) >= _sharemintAmount);
        (uint amountTokenA, uint amountTokenB) = liquidityMAth
            .removeLiquidityCalc(
                _sharemintAmount,
                totalShareInPool,
                tokenATotalBal,
                tokenBTotalBal
            );
        _reduceReserve(amountTokenA, amountTokenB);
        _burn(_recipient, _sharemintAmount);
        if (tokenA == WETH) {
            IERC20(tokenA).safeTransfer(Router, amountTokenA);
        } else {
            IERC20(tokenA).safeTransfer(_recipient, amountTokenA);
        }
        IERC20(tokenB).safeTransfer(_recipient, amountTokenB);
        totalShareInPool -= _sharemintAmount;
        return (amountTokenA, amountTokenB);
    }

    function updateReserve(
        uint _amountTokenA,
        uint _amountTokenB
    ) external onlyRouter {
        tokenATotalBal += _amountTokenA;
        tokenBTotalBal += _amountTokenB;
    }

    function _reduceReserve(uint _amountTokenA, uint _amountTokenB) internal {
        tokenATotalBal -= _amountTokenA;
        tokenBTotalBal -= _amountTokenB;
    }

    function __Router_init(address _router) internal {
        Router = _router;
    }
}
