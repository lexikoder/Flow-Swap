## Contract Addresses:
- Router: 0x3a45175B6dF92B7ECd949301d09Ff7a5C8A58a46
- Factory: 0x4Bb463407889Dcac3Bc9C96C8c24f5ce575aF480

Sepolia Testnet :
- Router: https://sepolia.etherscan.io/address/0x3a45175B6dF92B7ECd949301d09Ff7a5C8A58a46
- Factory: https://sepolia.etherscan.io/address/0x4Bb463407889Dcac3Bc9C96C8c24f5ce575aF480


## Foundry

**Foundry is a blazing fast, portable and modular toolkit for Ethereum application development written in Rust.**

Foundry consists of:

-   **Forge**: Ethereum testing framework (like Truffle, Hardhat and DappTools).
-   **Cast**: Swiss army knife for interacting with EVM smart contracts, sending transactions and getting chain data.
-   **Anvil**: Local Ethereum node, akin to Ganache, Hardhat Network.
-   **Chisel**: Fast, utilitarian, and verbose solidity REPL.

## Documentation

https://book.getfoundry.sh/

## Usage

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Format

```shell
$ forge fmt
```

### Gas Snapshots

```shell
$ forge snapshot
```

### Anvil

```shell
$ anvil
```

### Deploy

```shell
$ forge script script/Counter.s.sol:CounterScript --rpc-url <your_rpc_url> --private-key <your_private_key>
```

### Cast

```shell
$ cast <subcommand>
```

### Help

```shell
$ forge --help
$ anvil --help
$ cast --help
```


