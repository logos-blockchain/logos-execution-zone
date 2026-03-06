# Wallet CLI Completion

Completion scripts for the LSSA `wallet` command.

## ZSH

Works with both vanilla zsh and oh-my-zsh.

### Features

- Full completion for all wallet subcommands
- Contextual option completion for each command
- Dynamic account ID completion via `wallet account list`
- Descriptions for all commands and options

Note that only accounts created by the user auto-complete.
Preconfigured accounts and accounts only with `/` (no number) are not completed.

e.g.:

```
▶ wallet account list
Preconfigured Public/7wHg9sbJwc6h3NP1S9bekfAzB8CHifEcxKswCKUt3YQo,
Preconfigured Public/6iArKUXxhUJqS7kCaPNhwMWt3ro71PDyBj7jwAyE2VQV,
Preconfigured Private/3oCG8gqdKLMegw4rRfyaMQvuPHpcASt7xwttsmnZLSkw,
Preconfigured Private/AKTcXgJ1xoynta1Ec7y6Jso1z1JQtHqd7aPQ1h9er6xX,
/ Public/8DstRgMQrB2N9a7ymv98RDDbt8nctrP9ZzaNRSpKDZSu,
/0 Public/2gJJjtG9UivBGEhA1Jz6waZQx1cwfYupC5yvKEweHaeH,
/ Private/Bcv15B36bs1VqvQAdY6ZGFM1KioByNQQsB92KTNAx6u2
```

Only `Public/2gJJjtG9UivBGEhA1Jz6waZQx1cwfYupC5yvKEweHaeH` is used for completion.

### Supported Commands

| Command                | Description                                                 |
|------------------------|-------------------------------------------------------------|
| `wallet auth-transfer` | Authenticated transfer (init, send)                         |
| `wallet chain-info`    | Chain info queries (current-block-id, block, transaction)   |
| `wallet account`       | Account management (get, list, new, sync-private)           |
| `wallet pinata`        | Piñata faucet (claim)                                       |
| `wallet token`         | Token operations (new, send)                                |
| `wallet amm`           | AMM operations (new, swap, add-liquidity, remove-liquidity) |
| `wallet check-health`  | Health check                                                |

### Installation

#### Vanilla Zsh

1. Create a completions directory:

   ```sh
   mkdir -p ~/.zsh/completions
   ```

2. Copy the completion file:

   ```sh
   cp ./zsh/_wallet ~/.zsh/completions/
   ```

3. Add to your `~/.zshrc` (before any `compinit` call, or add these lines if you don't have one):

   ```sh
   fpath=(~/.zsh/completions $fpath)
   autoload -Uz compinit && compinit
   ```

4. Reload your shell:

   ```sh
   exec zsh
   ```

#### Oh-My-Zsh

1. Create the plugin directory and copy the file:

   ```sh
   mkdir -p ~/.oh-my-zsh/custom/plugins/wallet
   cp _wallet ~/.oh-my-zsh/custom/plugins/wallet/
   ```

2. Add `wallet` to your plugins array in `~/.zshrc`:

   ```sh
   plugins=(... wallet)
   ```

3. Reload your shell:

   ```sh
   exec zsh
   ```

### Requirements

The completion script calls `wallet account list` to dynamically fetch account IDs. Ensure the `wallet` command is in your `$PATH`.

### Usage

```sh
# Main commands
wallet <TAB>

# Account subcommands
wallet account <TAB>

# Options for auth-transfer send
wallet auth-transfer send --<TAB>

# Account types when creating
wallet account new <TAB>
# Shows: public  private

# Account IDs (fetched dynamically)
wallet account get --account-id <TAB>
# Shows: Public/...  Private/...
```

## Troubleshooting

### Completions not appearing

1. Check that `compinit` is called in your `.zshrc`
2. Rebuild the completion cache:

   ```sh
   rm -f ~/.zcompdump*
   exec zsh
   ```

### Account IDs not completing

Ensure `wallet account list` works from your command line.
