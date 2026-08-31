This repository includes a CLI for interacting with the Logos Blockchain. To install it, run the following command from the root of the repository:

```bash
cargo install --path wallet --force
```

To check that everythin is working, run `wallet help`.

## Available Wallet Commands

| Command                | Description                                                 |
|------------------------|-------------------------------------------------------------|
| `wallet auth-transfer` | Authenticated transfer (send)                               |
| `wallet chain-info`    | Chain info queries (current-block-id, block, transaction)   |
| `wallet account`       | Account management (get, list, new, sync-private)           |
| `wallet token`         | Token operations (new, send)                                |
| `wallet amm`           | AMM operations (new, swap, add-liquidity, remove-liquidity) |
| `wallet check-health`  | Health checks that the wallet is connected to the node      |
| `wallet config`        | Config Setup (get, set)                                     |
| `wallet restore-keys ` | Keys restore from a given password at given `depth`         |
| `wallet deploy-program`| Program deployment                                          |
| `wallet help`          | Help                                           |

Some completion scripts exists, see the [completions](./completions/README.md) folder.

