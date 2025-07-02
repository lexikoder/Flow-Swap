
// File: @openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol


// OpenZeppelin Contracts (last updated v5.3.0) (proxy/utils/Initializable.sol)

pragma solidity ^0.8.20;

/**
 * @dev This is a base contract to aid in writing upgradeable contracts, or any kind of contract that will be deployed
 * behind a proxy. Since proxied contracts do not make use of a constructor, it's common to move constructor logic to an
 * external initializer function, usually called `initialize`. It then becomes necessary to protect this initializer
 * function so it can only be called once. The {initializer} modifier provided by this contract will have this effect.
 *
 * The initialization functions use a version number. Once a version number is used, it is consumed and cannot be
 * reused. This mechanism prevents re-execution of each "step" but allows the creation of new initialization steps in
 * case an upgrade adds a module that needs to be initialized.
 *
 * For example:
 *
 * [.hljs-theme-light.nopadding]
 * ```solidity
 * contract MyToken is ERC20Upgradeable {
 *     function initialize() initializer public {
 *         __ERC20_init("MyToken", "MTK");
 *     }
 * }
 *
 * contract MyTokenV2 is MyToken, ERC20PermitUpgradeable {
 *     function initializeV2() reinitializer(2) public {
 *         __ERC20Permit_init("MyToken");
 *     }
 * }
 * ```
 *
 * TIP: To avoid leaving the proxy in an uninitialized state, the initializer function should be called as early as
 * possible by providing the encoded function call as the `_data` argument to {ERC1967Proxy-constructor}.
 *
 * CAUTION: When used with inheritance, manual care must be taken to not invoke a parent initializer twice, or to ensure
 * that all initializers are idempotent. This is not verified automatically as constructors are by Solidity.
 *
 * [CAUTION]
 * ====
 * Avoid leaving a contract uninitialized.
 *
 * An uninitialized contract can be taken over by an attacker. This applies to both a proxy and its implementation
 * contract, which may impact the proxy. To prevent the implementation contract from being used, you should invoke
 * the {_disableInitializers} function in the constructor to automatically lock it when it is deployed:
 *
 * [.hljs-theme-light.nopadding]
 * ```
 * /// @custom:oz-upgrades-unsafe-allow constructor
 * constructor() {
 *     _disableInitializers();
 * }
 * ```
 * ====
 */
abstract contract Initializable {
    /**
     * @dev Storage of the initializable contract.
     *
     * It's implemented on a custom ERC-7201 namespace to reduce the risk of storage collisions
     * when using with upgradeable contracts.
     *
     * @custom:storage-location erc7201:openzeppelin.storage.Initializable
     */
    struct InitializableStorage {
        /**
         * @dev Indicates that the contract has been initialized.
         */
        uint64 _initialized;
        /**
         * @dev Indicates that the contract is in the process of being initialized.
         */
        bool _initializing;
    }

    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.Initializable")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant INITIALIZABLE_STORAGE = 0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00;

    /**
     * @dev The contract is already initialized.
     */
    error InvalidInitialization();

    /**
     * @dev The contract is not initializing.
     */
    error NotInitializing();

    /**
     * @dev Triggered when the contract has been initialized or reinitialized.
     */
    event Initialized(uint64 version);

    /**
     * @dev A modifier that defines a protected initializer function that can be invoked at most once. In its scope,
     * `onlyInitializing` functions can be used to initialize parent contracts.
     *
     * Similar to `reinitializer(1)`, except that in the context of a constructor an `initializer` may be invoked any
     * number of times. This behavior in the constructor can be useful during testing and is not expected to be used in
     * production.
     *
     * Emits an {Initialized} event.
     */
    modifier initializer() {
        // solhint-disable-next-line var-name-mixedcase
        InitializableStorage storage $ = _getInitializableStorage();

        // Cache values to avoid duplicated sloads
        bool isTopLevelCall = !$._initializing;
        uint64 initialized = $._initialized;

        // Allowed calls:
        // - initialSetup: the contract is not in the initializing state and no previous version was
        //                 initialized
        // - construction: the contract is initialized at version 1 (no reinitialization) and the
        //                 current contract is just being deployed
        bool initialSetup = initialized == 0 && isTopLevelCall;
        bool construction = initialized == 1 && address(this).code.length == 0;

        if (!initialSetup && !construction) {
            revert InvalidInitialization();
        }
        $._initialized = 1;
        if (isTopLevelCall) {
            $._initializing = true;
        }
        _;
        if (isTopLevelCall) {
            $._initializing = false;
            emit Initialized(1);
        }
    }

    /**
     * @dev A modifier that defines a protected reinitializer function that can be invoked at most once, and only if the
     * contract hasn't been initialized to a greater version before. In its scope, `onlyInitializing` functions can be
     * used to initialize parent contracts.
     *
     * A reinitializer may be used after the original initialization step. This is essential to configure modules that
     * are added through upgrades and that require initialization.
     *
     * When `version` is 1, this modifier is similar to `initializer`, except that functions marked with `reinitializer`
     * cannot be nested. If one is invoked in the context of another, execution will revert.
     *
     * Note that versions can jump in increments greater than 1; this implies that if multiple reinitializers coexist in
     * a contract, executing them in the right order is up to the developer or operator.
     *
     * WARNING: Setting the version to 2**64 - 1 will prevent any future reinitialization.
     *
     * Emits an {Initialized} event.
     */
    modifier reinitializer(uint64 version) {
        // solhint-disable-next-line var-name-mixedcase
        InitializableStorage storage $ = _getInitializableStorage();

        if ($._initializing || $._initialized >= version) {
            revert InvalidInitialization();
        }
        $._initialized = version;
        $._initializing = true;
        _;
        $._initializing = false;
        emit Initialized(version);
    }

    /**
     * @dev Modifier to protect an initialization function so that it can only be invoked by functions with the
     * {initializer} and {reinitializer} modifiers, directly or indirectly.
     */
    modifier onlyInitializing() {
        _checkInitializing();
        _;
    }

    /**
     * @dev Reverts if the contract is not in an initializing state. See {onlyInitializing}.
     */
    function _checkInitializing() internal view virtual {
        if (!_isInitializing()) {
            revert NotInitializing();
        }
    }

    /**
     * @dev Locks the contract, preventing any future reinitialization. This cannot be part of an initializer call.
     * Calling this in the constructor of a contract will prevent that contract from being initialized or reinitialized
     * to any version. It is recommended to use this to lock implementation contracts that are designed to be called
     * through proxies.
     *
     * Emits an {Initialized} event the first time it is successfully executed.
     */
    function _disableInitializers() internal virtual {
        // solhint-disable-next-line var-name-mixedcase
        InitializableStorage storage $ = _getInitializableStorage();

        if ($._initializing) {
            revert InvalidInitialization();
        }
        if ($._initialized != type(uint64).max) {
            $._initialized = type(uint64).max;
            emit Initialized(type(uint64).max);
        }
    }

    /**
     * @dev Returns the highest version that has been initialized. See {reinitializer}.
     */
    function _getInitializedVersion() internal view returns (uint64) {
        return _getInitializableStorage()._initialized;
    }

    /**
     * @dev Returns `true` if the contract is currently initializing. See {onlyInitializing}.
     */
    function _isInitializing() internal view returns (bool) {
        return _getInitializableStorage()._initializing;
    }

    /**
     * @dev Pointer to storage slot. Allows integrators to override it with a custom storage location.
     *
     * NOTE: Consider following the ERC-7201 formula to derive storage locations.
     */
    function _initializableStorageSlot() internal pure virtual returns (bytes32) {
        return INITIALIZABLE_STORAGE;
    }

    /**
     * @dev Returns a pointer to the storage namespace.
     */
    // solhint-disable-next-line var-name-mixedcase
    function _getInitializableStorage() private pure returns (InitializableStorage storage $) {
        bytes32 slot = _initializableStorageSlot();
        assembly {
            $.slot := slot
        }
    }
}

// File: @openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol


// OpenZeppelin Contracts (last updated v5.1.0) (utils/ReentrancyGuard.sol)

pragma solidity ^0.8.20;


/**
 * @dev Contract module that helps prevent reentrant calls to a function.
 *
 * Inheriting from `ReentrancyGuard` will make the {nonReentrant} modifier
 * available, which can be applied to functions to make sure there are no nested
 * (reentrant) calls to them.
 *
 * Note that because there is a single `nonReentrant` guard, functions marked as
 * `nonReentrant` may not call one another. This can be worked around by making
 * those functions `private`, and then adding `external` `nonReentrant` entry
 * points to them.
 *
 * TIP: If EIP-1153 (transient storage) is available on the chain you're deploying at,
 * consider using {ReentrancyGuardTransient} instead.
 *
 * TIP: If you would like to learn more about reentrancy and alternative ways
 * to protect against it, check out our blog post
 * https://blog.openzeppelin.com/reentrancy-after-istanbul/[Reentrancy After Istanbul].
 */
abstract contract ReentrancyGuardUpgradeable is Initializable {
    // Booleans are more expensive than uint256 or any type that takes up a full
    // word because each write operation emits an extra SLOAD to first read the
    // slot's contents, replace the bits taken up by the boolean, and then write
    // back. This is the compiler's defense against contract upgrades and
    // pointer aliasing, and it cannot be disabled.

    // The values being non-zero value makes deployment a bit more expensive,
    // but in exchange the refund on every call to nonReentrant will be lower in
    // amount. Since refunds are capped to a percentage of the total
    // transaction's gas, it is best to keep them low in cases like this one, to
    // increase the likelihood of the full refund coming into effect.
    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;

    /// @custom:storage-location erc7201:openzeppelin.storage.ReentrancyGuard
    struct ReentrancyGuardStorage {
        uint256 _status;
    }

    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.ReentrancyGuard")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant ReentrancyGuardStorageLocation = 0x9b779b17422d0df92223018b32b4d1fa46e071723d6817e2486d003becc55f00;

    function _getReentrancyGuardStorage() private pure returns (ReentrancyGuardStorage storage $) {
        assembly {
            $.slot := ReentrancyGuardStorageLocation
        }
    }

    /**
     * @dev Unauthorized reentrant call.
     */
    error ReentrancyGuardReentrantCall();

    function __ReentrancyGuard_init() internal onlyInitializing {
        __ReentrancyGuard_init_unchained();
    }

    function __ReentrancyGuard_init_unchained() internal onlyInitializing {
        ReentrancyGuardStorage storage $ = _getReentrancyGuardStorage();
        $._status = NOT_ENTERED;
    }

    /**
     * @dev Prevents a contract from calling itself, directly or indirectly.
     * Calling a `nonReentrant` function from another `nonReentrant`
     * function is not supported. It is possible to prevent this from happening
     * by making the `nonReentrant` function external, and making it call a
     * `private` function that does the actual work.
     */
    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    function _nonReentrantBefore() private {
        ReentrancyGuardStorage storage $ = _getReentrancyGuardStorage();
        // On the first call to nonReentrant, _status will be NOT_ENTERED
        if ($._status == ENTERED) {
            revert ReentrancyGuardReentrantCall();
        }

        // Any calls to nonReentrant after this point will fail
        $._status = ENTERED;
    }

    function _nonReentrantAfter() private {
        ReentrancyGuardStorage storage $ = _getReentrancyGuardStorage();
        // By storing the original value once again, a refund is triggered (see
        // https://eips.ethereum.org/EIPS/eip-2200)
        $._status = NOT_ENTERED;
    }

    /**
     * @dev Returns true if the reentrancy guard is currently set to "entered", which indicates there is a
     * `nonReentrant` function in the call stack.
     */
    function _reentrancyGuardEntered() internal view returns (bool) {
        ReentrancyGuardStorage storage $ = _getReentrancyGuardStorage();
        return $._status == ENTERED;
    }
}

// File: src/interfaces/IWETH.sol


pragma solidity 0.8.20;

interface IWETH {
    function deposit() external payable;

    function withdraw(
        uint256
    ) external;
}

// File: src/interfaces/IFactory.sol


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
// File: src/libraries/math.sol


pragma solidity 0.8.20;

// a library for performing various math operations

library math {
    function min(uint x, uint y) internal pure returns (uint z) {
        z = x < y ? x : y;
    }

    // babylonian method (https://en.wikipedia.org/wiki/Methods_of_computing_square_roots#Babylonian_method)
    function sqrt(uint y) internal pure returns (uint z) {
        if (y > 3) {
            z = y;
            uint x = y / 2 + 1;
            while (x < z) {
                z = x;
                x = (y / x + x) / 2;
            }
        } else if (y != 0) {
            z = 1;
        }
    }
}
// File: src/libraries/liquidityMath.sol


pragma solidity ^0.8.20;



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
// File: src/libraries/swapMath.sol


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

// File: src/interfaces/IPair.sol


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
// File: @openzeppelin/contracts/token/ERC20/IERC20.sol


// OpenZeppelin Contracts (last updated v5.1.0) (token/ERC20/IERC20.sol)

pragma solidity ^0.8.20;

/**
 * @dev Interface of the ERC-20 standard as defined in the ERC.
 */
interface IERC20 {
    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);

    /**
     * @dev Returns the value of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the value of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves a `value` amount of tokens from the caller's account to `to`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address to, uint256 value) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender) external view returns (uint256);

    /**
     * @dev Sets a `value` amount of tokens as the allowance of `spender` over the
     * caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 value) external returns (bool);

    /**
     * @dev Moves a `value` amount of tokens from `from` to `to` using the
     * allowance mechanism. `value` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

// File: @openzeppelin/contracts/interfaces/IERC20.sol


// OpenZeppelin Contracts (last updated v5.0.0) (interfaces/IERC20.sol)

pragma solidity ^0.8.20;


// File: @openzeppelin/contracts/utils/introspection/IERC165.sol


// OpenZeppelin Contracts (last updated v5.1.0) (utils/introspection/IERC165.sol)

pragma solidity ^0.8.20;

/**
 * @dev Interface of the ERC-165 standard, as defined in the
 * https://eips.ethereum.org/EIPS/eip-165[ERC].
 *
 * Implementers can declare support of contract interfaces, which can then be
 * queried by others ({ERC165Checker}).
 *
 * For an implementation, see {ERC165}.
 */
interface IERC165 {
    /**
     * @dev Returns true if this contract implements the interface defined by
     * `interfaceId`. See the corresponding
     * https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[ERC section]
     * to learn more about how these ids are created.
     *
     * This function call must use less than 30 000 gas.
     */
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

// File: @openzeppelin/contracts/interfaces/IERC165.sol


// OpenZeppelin Contracts (last updated v5.0.0) (interfaces/IERC165.sol)

pragma solidity ^0.8.20;


// File: @openzeppelin/contracts/interfaces/IERC1363.sol


// OpenZeppelin Contracts (last updated v5.1.0) (interfaces/IERC1363.sol)

pragma solidity ^0.8.20;



/**
 * @title IERC1363
 * @dev Interface of the ERC-1363 standard as defined in the https://eips.ethereum.org/EIPS/eip-1363[ERC-1363].
 *
 * Defines an extension interface for ERC-20 tokens that supports executing code on a recipient contract
 * after `transfer` or `transferFrom`, or code on a spender contract after `approve`, in a single transaction.
 */
interface IERC1363 is IERC20, IERC165 {
    /*
     * Note: the ERC-165 identifier for this interface is 0xb0202a11.
     * 0xb0202a11 ===
     *   bytes4(keccak256('transferAndCall(address,uint256)')) ^
     *   bytes4(keccak256('transferAndCall(address,uint256,bytes)')) ^
     *   bytes4(keccak256('transferFromAndCall(address,address,uint256)')) ^
     *   bytes4(keccak256('transferFromAndCall(address,address,uint256,bytes)')) ^
     *   bytes4(keccak256('approveAndCall(address,uint256)')) ^
     *   bytes4(keccak256('approveAndCall(address,uint256,bytes)'))
     */

    /**
     * @dev Moves a `value` amount of tokens from the caller's account to `to`
     * and then calls {IERC1363Receiver-onTransferReceived} on `to`.
     * @param to The address which you want to transfer to.
     * @param value The amount of tokens to be transferred.
     * @return A boolean value indicating whether the operation succeeded unless throwing.
     */
    function transferAndCall(address to, uint256 value) external returns (bool);

    /**
     * @dev Moves a `value` amount of tokens from the caller's account to `to`
     * and then calls {IERC1363Receiver-onTransferReceived} on `to`.
     * @param to The address which you want to transfer to.
     * @param value The amount of tokens to be transferred.
     * @param data Additional data with no specified format, sent in call to `to`.
     * @return A boolean value indicating whether the operation succeeded unless throwing.
     */
    function transferAndCall(address to, uint256 value, bytes calldata data) external returns (bool);

    /**
     * @dev Moves a `value` amount of tokens from `from` to `to` using the allowance mechanism
     * and then calls {IERC1363Receiver-onTransferReceived} on `to`.
     * @param from The address which you want to send tokens from.
     * @param to The address which you want to transfer to.
     * @param value The amount of tokens to be transferred.
     * @return A boolean value indicating whether the operation succeeded unless throwing.
     */
    function transferFromAndCall(address from, address to, uint256 value) external returns (bool);

    /**
     * @dev Moves a `value` amount of tokens from `from` to `to` using the allowance mechanism
     * and then calls {IERC1363Receiver-onTransferReceived} on `to`.
     * @param from The address which you want to send tokens from.
     * @param to The address which you want to transfer to.
     * @param value The amount of tokens to be transferred.
     * @param data Additional data with no specified format, sent in call to `to`.
     * @return A boolean value indicating whether the operation succeeded unless throwing.
     */
    function transferFromAndCall(address from, address to, uint256 value, bytes calldata data) external returns (bool);

    /**
     * @dev Sets a `value` amount of tokens as the allowance of `spender` over the
     * caller's tokens and then calls {IERC1363Spender-onApprovalReceived} on `spender`.
     * @param spender The address which will spend the funds.
     * @param value The amount of tokens to be spent.
     * @return A boolean value indicating whether the operation succeeded unless throwing.
     */
    function approveAndCall(address spender, uint256 value) external returns (bool);

    /**
     * @dev Sets a `value` amount of tokens as the allowance of `spender` over the
     * caller's tokens and then calls {IERC1363Spender-onApprovalReceived} on `spender`.
     * @param spender The address which will spend the funds.
     * @param value The amount of tokens to be spent.
     * @param data Additional data with no specified format, sent in call to `spender`.
     * @return A boolean value indicating whether the operation succeeded unless throwing.
     */
    function approveAndCall(address spender, uint256 value, bytes calldata data) external returns (bool);
}

// File: @openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol


// OpenZeppelin Contracts (last updated v5.3.0) (token/ERC20/utils/SafeERC20.sol)

pragma solidity ^0.8.20;



/**
 * @title SafeERC20
 * @dev Wrappers around ERC-20 operations that throw on failure (when the token
 * contract returns false). Tokens that return no value (and instead revert or
 * throw on failure) are also supported, non-reverting calls are assumed to be
 * successful.
 * To use this library you can add a `using SafeERC20 for IERC20;` statement to your contract,
 * which allows you to call the safe operations as `token.safeTransfer(...)`, etc.
 */
library SafeERC20 {
    /**
     * @dev An operation with an ERC-20 token failed.
     */
    error SafeERC20FailedOperation(address token);

    /**
     * @dev Indicates a failed `decreaseAllowance` request.
     */
    error SafeERC20FailedDecreaseAllowance(address spender, uint256 currentAllowance, uint256 requestedDecrease);

    /**
     * @dev Transfer `value` amount of `token` from the calling contract to `to`. If `token` returns no value,
     * non-reverting calls are assumed to be successful.
     */
    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeCall(token.transfer, (to, value)));
    }

    /**
     * @dev Transfer `value` amount of `token` from `from` to `to`, spending the approval given by `from` to the
     * calling contract. If `token` returns no value, non-reverting calls are assumed to be successful.
     */
    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeCall(token.transferFrom, (from, to, value)));
    }

    /**
     * @dev Variant of {safeTransfer} that returns a bool instead of reverting if the operation is not successful.
     */
    function trySafeTransfer(IERC20 token, address to, uint256 value) internal returns (bool) {
        return _callOptionalReturnBool(token, abi.encodeCall(token.transfer, (to, value)));
    }

    /**
     * @dev Variant of {safeTransferFrom} that returns a bool instead of reverting if the operation is not successful.
     */
    function trySafeTransferFrom(IERC20 token, address from, address to, uint256 value) internal returns (bool) {
        return _callOptionalReturnBool(token, abi.encodeCall(token.transferFrom, (from, to, value)));
    }

    /**
     * @dev Increase the calling contract's allowance toward `spender` by `value`. If `token` returns no value,
     * non-reverting calls are assumed to be successful.
     *
     * IMPORTANT: If the token implements ERC-7674 (ERC-20 with temporary allowance), and if the "client"
     * smart contract uses ERC-7674 to set temporary allowances, then the "client" smart contract should avoid using
     * this function. Performing a {safeIncreaseAllowance} or {safeDecreaseAllowance} operation on a token contract
     * that has a non-zero temporary allowance (for that particular owner-spender) will result in unexpected behavior.
     */
    function safeIncreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        uint256 oldAllowance = token.allowance(address(this), spender);
        forceApprove(token, spender, oldAllowance + value);
    }

    /**
     * @dev Decrease the calling contract's allowance toward `spender` by `requestedDecrease`. If `token` returns no
     * value, non-reverting calls are assumed to be successful.
     *
     * IMPORTANT: If the token implements ERC-7674 (ERC-20 with temporary allowance), and if the "client"
     * smart contract uses ERC-7674 to set temporary allowances, then the "client" smart contract should avoid using
     * this function. Performing a {safeIncreaseAllowance} or {safeDecreaseAllowance} operation on a token contract
     * that has a non-zero temporary allowance (for that particular owner-spender) will result in unexpected behavior.
     */
    function safeDecreaseAllowance(IERC20 token, address spender, uint256 requestedDecrease) internal {
        unchecked {
            uint256 currentAllowance = token.allowance(address(this), spender);
            if (currentAllowance < requestedDecrease) {
                revert SafeERC20FailedDecreaseAllowance(spender, currentAllowance, requestedDecrease);
            }
            forceApprove(token, spender, currentAllowance - requestedDecrease);
        }
    }

    /**
     * @dev Set the calling contract's allowance toward `spender` to `value`. If `token` returns no value,
     * non-reverting calls are assumed to be successful. Meant to be used with tokens that require the approval
     * to be set to zero before setting it to a non-zero value, such as USDT.
     *
     * NOTE: If the token implements ERC-7674, this function will not modify any temporary allowance. This function
     * only sets the "standard" allowance. Any temporary allowance will remain active, in addition to the value being
     * set here.
     */
    function forceApprove(IERC20 token, address spender, uint256 value) internal {
        bytes memory approvalCall = abi.encodeCall(token.approve, (spender, value));

        if (!_callOptionalReturnBool(token, approvalCall)) {
            _callOptionalReturn(token, abi.encodeCall(token.approve, (spender, 0)));
            _callOptionalReturn(token, approvalCall);
        }
    }

    /**
     * @dev Performs an {ERC1363} transferAndCall, with a fallback to the simple {ERC20} transfer if the target has no
     * code. This can be used to implement an {ERC721}-like safe transfer that rely on {ERC1363} checks when
     * targeting contracts.
     *
     * Reverts if the returned value is other than `true`.
     */
    function transferAndCallRelaxed(IERC1363 token, address to, uint256 value, bytes memory data) internal {
        if (to.code.length == 0) {
            safeTransfer(token, to, value);
        } else if (!token.transferAndCall(to, value, data)) {
            revert SafeERC20FailedOperation(address(token));
        }
    }

    /**
     * @dev Performs an {ERC1363} transferFromAndCall, with a fallback to the simple {ERC20} transferFrom if the target
     * has no code. This can be used to implement an {ERC721}-like safe transfer that rely on {ERC1363} checks when
     * targeting contracts.
     *
     * Reverts if the returned value is other than `true`.
     */
    function transferFromAndCallRelaxed(
        IERC1363 token,
        address from,
        address to,
        uint256 value,
        bytes memory data
    ) internal {
        if (to.code.length == 0) {
            safeTransferFrom(token, from, to, value);
        } else if (!token.transferFromAndCall(from, to, value, data)) {
            revert SafeERC20FailedOperation(address(token));
        }
    }

    /**
     * @dev Performs an {ERC1363} approveAndCall, with a fallback to the simple {ERC20} approve if the target has no
     * code. This can be used to implement an {ERC721}-like safe transfer that rely on {ERC1363} checks when
     * targeting contracts.
     *
     * NOTE: When the recipient address (`to`) has no code (i.e. is an EOA), this function behaves as {forceApprove}.
     * Opposedly, when the recipient address (`to`) has code, this function only attempts to call {ERC1363-approveAndCall}
     * once without retrying, and relies on the returned value to be true.
     *
     * Reverts if the returned value is other than `true`.
     */
    function approveAndCallRelaxed(IERC1363 token, address to, uint256 value, bytes memory data) internal {
        if (to.code.length == 0) {
            forceApprove(token, to, value);
        } else if (!token.approveAndCall(to, value, data)) {
            revert SafeERC20FailedOperation(address(token));
        }
    }

    /**
     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement
     * on the return value: the return value is optional (but if data is returned, it must not be false).
     * @param token The token targeted by the call.
     * @param data The call data (encoded using abi.encode or one of its variants).
     *
     * This is a variant of {_callOptionalReturnBool} that reverts if call fails to meet the requirements.
     */
    function _callOptionalReturn(IERC20 token, bytes memory data) private {
        uint256 returnSize;
        uint256 returnValue;
        assembly ("memory-safe") {
            let success := call(gas(), token, 0, add(data, 0x20), mload(data), 0, 0x20)
            // bubble errors
            if iszero(success) {
                let ptr := mload(0x40)
                returndatacopy(ptr, 0, returndatasize())
                revert(ptr, returndatasize())
            }
            returnSize := returndatasize()
            returnValue := mload(0)
        }

        if (returnSize == 0 ? address(token).code.length == 0 : returnValue != 1) {
            revert SafeERC20FailedOperation(address(token));
        }
    }

    /**
     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement
     * on the return value: the return value is optional (but if data is returned, it must not be false).
     * @param token The token targeted by the call.
     * @param data The call data (encoded using abi.encode or one of its variants).
     *
     * This is a variant of {_callOptionalReturn} that silently catches all reverts and returns a bool instead.
     */
    function _callOptionalReturnBool(IERC20 token, bytes memory data) private returns (bool) {
        bool success;
        uint256 returnSize;
        uint256 returnValue;
        assembly ("memory-safe") {
            success := call(gas(), token, 0, add(data, 0x20), mload(data), 0, 0x20)
            returnSize := returndatasize()
            returnValue := mload(0)
        }
        return success && (returnSize == 0 ? address(token).code.length > 0 : returnValue == 1);
    }
}

// File: src/Router.sol


pragma solidity 0.8.20;









contract Router is ReentrancyGuardUpgradeable {
    using SafeERC20 for IERC20;
    address public WETH;
    address public factory;

    constructor(address _weth, address _factory) {
        WETH = _weth;
        factory = _factory;
    }

    modifier validAddress(address _address) {
        require(_address != address(0), "address zero not allowed");
        _;
    }

    modifier validAmount(uint256 _amount) {
        require(_amount > 0, "amount zero not allowed");
        _;
    }

    modifier validAmountTokenAB(uint256 _amountTokenA, uint256 _amountTokenB) {
        require(
            _amountTokenA > 0 && _amountTokenB > 0,
            "amount zero not allowed"
        );
        _;
    }

    modifier beforeDeadline(uint _deadline) {
        require(block.timestamp <= _deadline, "Deadline has passed");
        _;
    }

    function addLiquidity(
        address tokenA,
        address tokenB,
        uint _amountTokenA,
        uint _amountTokenB,
        uint _deadline
    ) public beforeDeadline(_deadline) nonReentrant {
        require(
            _amountTokenA > 0 && _amountTokenB > 0,
            "amount zero not allowed"
        );
        address pairAddress = IFactory(factory)._pairAddress(tokenA, tokenB);
        require(pairAddress != address(0), "Pair not deployed");

        uint tokenAtotalBal = IPair(pairAddress).tokenATotalBal();
        uint tokenBtotalBal = IPair(pairAddress).tokenBTotalBal();
        if (tokenAtotalBal == 0 && tokenBtotalBal == 0) {
            IERC20(tokenA).safeTransferFrom(
                msg.sender,
                pairAddress,
                _amountTokenA
            );
            IERC20(tokenB).safeTransferFrom(
                msg.sender,
                pairAddress,
                _amountTokenB
            );
        } else {
            uint amountTokenB = liquidityMAth.addliquidityCalcTokenB(
                _amountTokenA,
                tokenAtotalBal,
                tokenBtotalBal
            );
            IERC20(tokenA).safeTransferFrom(
                msg.sender,
                pairAddress,
                _amountTokenA
            );
            IERC20(tokenB).safeTransferFrom(
                msg.sender,
                pairAddress,
                amountTokenB
            );
            require(
                amountTokenB == _amountTokenB,
                "Incorrect liquidity amount"
            );
        }
        //   uint amountTokenA = liquidityMAth.addliquidityCalcTokenA(amountTokenB,tokenAtotalBal,tokenBtotalBal);

        IPair(pairAddress).updateReserve(_amountTokenA, _amountTokenB);
        IPair(pairAddress).mint(msg.sender, _amountTokenA, _amountTokenB);
    }

    function removeLiquidity(
        address pairAddress,
        uint _sharemintAmount,
        uint _deadline
    )
        public
        validAddress(pairAddress)
        validAmount(_sharemintAmount)
        beforeDeadline(_deadline)
        nonReentrant
    {
        IPair(pairAddress).burn(msg.sender, _sharemintAmount);
    }

    function addLiquidityEThPair(
        address tokenB,
        uint _amountTokenB,
        uint _deadline
    ) public payable beforeDeadline(_deadline) nonReentrant {
        _wrap();
        require(msg.value > 0 && _amountTokenB > 0, "amount zero not allowed");
        address pairAddress = IFactory(factory)._pairAddress(WETH, tokenB);
        require(pairAddress != address(0), "Pair not deployed");

        uint tokenAtotalBal = IPair(pairAddress).tokenATotalBal();
        uint tokenBtotalBal = IPair(pairAddress).tokenBTotalBal();
        if (tokenAtotalBal == 0 && tokenBtotalBal == 0) {
            IERC20(WETH).safeTransferFrom(
                address(this),
                pairAddress,
                msg.value
            );
            IERC20(tokenB).safeTransferFrom(
                msg.sender,
                pairAddress,
                _amountTokenB
            );
        } else {
            uint amountTokenB = liquidityMAth.addliquidityCalcTokenB(
                msg.value,
                tokenAtotalBal,
                tokenBtotalBal
            );
            //   uint amountTokenA = liquidityMAth.addliquidityCalcTokenA(amountTokenB,tokenAtotalBal,tokenBtotalBal);
            IERC20(WETH).safeTransferFrom(
                address(this),
                pairAddress,
                msg.value
            );
            IERC20(tokenB).safeTransferFrom(
                msg.sender,
                pairAddress,
                amountTokenB
            );
            require(
                amountTokenB == _amountTokenB,
                "Incorrect liquidity amount"
            );
        }

        IPair(pairAddress).updateReserve(msg.value, _amountTokenB);
        IPair(pairAddress).mint(msg.sender, msg.value, _amountTokenB);
    }

    function removeLiquidityEThPair(
        address pairAddress,
        uint _sharemintAmount,
        uint _deadline
    )
        public
        validAddress(pairAddress)
        validAmount(_sharemintAmount)
        beforeDeadline(_deadline)
        nonReentrant
    {
        (uint amountTokenA, ) = IPair(pairAddress).burn(
            msg.sender,
            _sharemintAmount
        );
        _unwrap(amountTokenA);
        (bool success, ) = msg.sender.call{value: amountTokenA}(""); // Safely transfer Ether
        require(success, "Transfer failed");
    }

    function swapTokenForToken(
        address tokenIn,
        address tokenOut,
        uint amountTokenIn,
        uint amountTokenOut,
        uint _deadline
    )
        public
        validAmountTokenAB(amountTokenIn, amountTokenOut)
        beforeDeadline(_deadline)
        nonReentrant
    {
        require(
            tokenIn != address(0) && tokenOut != address(0),
            "address zero not allowed"
        );

        address pairAddress = IFactory(factory)._pairAddress(tokenIn, tokenOut);

        IERC20(tokenIn).safeTransferFrom(
            msg.sender,
            pairAddress,
            amountTokenIn
        );

        IPair(pairAddress).swap(
            msg.sender,
            tokenIn,
            tokenOut,
            amountTokenIn,
            amountTokenOut
        );
    }

    function swapTokenForEth(
        address tokenIn,
        uint amountTokenIn,
        uint amountTokenOut,
        uint _deadline
    ) public beforeDeadline(_deadline) {
        require(tokenIn != address(0), "address zero not allowed");
        address pairAddress = IFactory(factory)._pairAddress(tokenIn, WETH);
        uint _amountTokenOut = IPair(pairAddress).swap(
            msg.sender,
            tokenIn,
            WETH,
            amountTokenIn,
            amountTokenOut
        );
        _unwrap(_amountTokenOut);
        IERC20(tokenIn).safeTransferFrom(
            msg.sender,
            pairAddress,
            amountTokenIn
        );
        (bool success, ) = msg.sender.call{value: _amountTokenOut}(""); // Safely transfer Ether
        require(success, "Transfer failed");
    }
    function swapEthForToken(
        address tokenOut,
        uint amountTokenOut,
        uint _deadline
    ) public payable beforeDeadline(_deadline) {
        _wrap();
        require(tokenOut != address(0), "address zero not allowed");
        address pairAddress = IFactory(factory)._pairAddress(WETH, tokenOut);
        IPair(pairAddress).swap(
            msg.sender,
            WETH,
            tokenOut,
            msg.value,
            amountTokenOut
        );
    }

    function _wrap() private {
        require(msg.value > 0, "2001");
        IWETH(WETH).deposit{value: msg.value}();
    }

    function _unwrap(uint256 _amount) private validAmount(_amount) {
        IWETH(WETH).withdraw(_amount);
    }

    function amountLiquidityB(
        address tokenA,
        address tokenB,
        uint _tokenAmountA
    ) public view returns (uint) {
        address pairAddress = IFactory(factory)._pairAddress(tokenA, tokenB);
        uint tokenAtotalBal = IPair(pairAddress).tokenATotalBal();
        uint tokenBtotalBal = IPair(pairAddress).tokenBTotalBal();
        uint amountTokenB = liquidityMAth.addliquidityCalcTokenB(
            _tokenAmountA,
            tokenAtotalBal,
            tokenBtotalBal
        );
        return amountTokenB;
    }

    function amountLiquidityBEth(
        address tokenB,
        uint _tokenAmountA
    ) public view returns (uint) {
        address pairAddress = IFactory(factory)._pairAddress(WETH, tokenB);
        uint tokenAtotalBal = IPair(pairAddress).tokenATotalBal();
        uint tokenBtotalBal = IPair(pairAddress).tokenBTotalBal();
        uint amountTokenB = liquidityMAth.addliquidityCalcTokenB(
            _tokenAmountA,
            tokenAtotalBal,
            tokenBtotalBal
        );
        return amountTokenB;
    }

    function amountOftokenOut(
        address tokenIn,
        address tokenOut,
        uint amountTokenIn
    ) public view returns (uint) {
        address pairAddress = IFactory(factory)._pairAddress(tokenIn, tokenOut);
        address tokenA = IPair(pairAddress).tokenA();

        uint tokenAtotalBal = IPair(pairAddress).tokenATotalBal();
        uint tokenBtotalBal = IPair(pairAddress).tokenBTotalBal();

        uint tokenAmountOut;
        uint fee = IFactory(factory).fee();

        if (tokenA == tokenIn) {
            tokenAmountOut = swapMAth.swapToTokenB(
                amountTokenIn,
                tokenAtotalBal,
                tokenBtotalBal,
                fee
            );
        } else {
            tokenAmountOut = swapMAth.swapToTokenB(
                amountTokenIn,
                tokenBtotalBal,
                tokenAtotalBal,
                fee
            );
        }

        return tokenAmountOut;
    }

    receive() external payable {}
}
