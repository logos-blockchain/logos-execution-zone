This tutorial focuses on custom tokens using the Token program. As of now, you have used the authenticated-transfers program for native tokens. The Token program is for creating and managing custom tokens. By the end, you will have practiced:
1. Creating new tokens.
2. Transferring custom tokens.

> [!Important]
> The Token program is a single program that creates and manages all tokens, so you do not deploy a new program for each token.
> Token program accounts fall into two types:
> - Token definition accounts: store token metadata such as name and total supply. This account is the token’s identifier.
> - Token holding accounts: store balances and the definition ID they belong to.

The CLI provides commands to execute the Token program. Run `wallet token` to see the options:

```bash
Commands:
  new   Produce a new token
  send  Send tokens from one account to another with variable privacy
  help  Print this message or the help of the given subcommand(s)
```

## 1. Creating new tokens

Use `wallet token new` to execute the `New` function of the Token program. The command expects:
- A token name.
- A total supply.
- Two uninitialized accounts:
- One for the token definition account.
- One for the token holding account that receives the initial supply.

### a. Public definition account and public supply account

1. Create two new public accounts:

```bash
wallet account new public

# Output:
Generated new account with account_id Public/4X9kAcnCZ1Ukkbm3nywW9xfCNPK8XaMWCk3zfs1sP4J7
```

```bash
wallet account new public

# Output:
Generated new account with account_id Public/9RRSMm3w99uCD2Jp2Mqqf6dfc8me2tkFRE9HeU2DFftw
```

2. Create the token (Token A):

```bash
wallet token new \
    --name TOKENA \
    --total-supply 1337 \
    --definition-account-id Public/4X9kAcnCZ1Ukkbm3nywW9xfCNPK8XaMWCk3zfs1sP4J7 \
    --supply-account-id Public/9RRSMm3w99uCD2Jp2Mqqf6dfc8me2tkFRE9HeU2DFftw
```

3. Inspect the initialized accounts:

```bash
wallet account get --account-id Public/4X9kAcnCZ1Ukkbm3nywW9xfCNPK8XaMWCk3zfs1sP4J7

# Output:
Token program definition record
{"account_type":"Token definition","name":"TOKENA","total_supply":1337}
```

```bash
wallet account get --account-id Public/9RRSMm3w99uCD2Jp2Mqqf6dfc8me2tkFRE9HeU2DFftw

# Output:
Token program holding record
{"account_type":"Token holding","definition_id":"4X9kAcnCZ1Ukkbm3nywW9xfCNPK8XaMWCk3zfs1sP4J7","balance":1337}
```

### b. Public definition account and private supply account

1. Create fresh accounts for this example:

> [!Important]
> You cannot reuse the accounts from the previous example. Create new ones here.

```bash
wallet account new public

# Output:
Generated new account with account_id Public/GQ3C8rbprTtQUCvkuVBRu3v9wvUvjafCMFqoSPvTEVii
```

```bash
wallet account new private

# Output:
Generated new account with account_id Private/HMRHZdPw4pbyPVZHNGrV6K5AA95wACFsHTRST84fr3CF
With npk 6a2dfe433cf28e525aa0196d719be3c16146f7ee358ca39595323f94fde38f93
With vpk 03d59abf4bee974cc12ddb44641c19f0b5441fef39191f047c988c29a77252a577
```

2. Create the token (Token B):

```bash
wallet token new \
    --name TOKENB \
    --total-supply 7331 \
    --definition-account-id Public/GQ3C8rbprTtQUCvkuVBRu3v9wvUvjafCMFqoSPvTEVii \
    --supply-account-id Private/HMRHZdPw4pbyPVZHNGrV6K5AA95wACFsHTRST84fr3CF
```

3. Inspect the accounts:

```bash
wallet account get --account-id Public/GQ3C8rbprTtQUCvkuVBRu3v9wvUvjafCMFqoSPvTEVii

# Output:
Token program definition record
{"account_type":"Token definition","name":"TOKENB","total_supply":7331}
```

```bash
wallet account get --account-id Private/HMRHZdPw4pbyPVZHNGrV6K5AA95wACFsHTRST84fr3CF

# Output:
Token program holding record
{"account_type":"Token holding","definition_id":"GQ3C8rbprTtQUCvkuVBRu3v9wvUvjafCMFqoSPvTEVii","balance":7331}
```

> [!Important]
> As a private account, the supply account is visible only in your local wallet storage.

## 2. Custom token transfers

The Token program can move balances between token holding accounts. If the recipient account is uninitialized, the token program will automatically claim it. Use `wallet token send` to execute a transfer.

### a. Create a recipient account

```bash
wallet account new public

# Output:
Generated new account with account_id Public/88f2zeTgiv9LUthQwPJbrmufb9SiDfmpCs47B7vw6Gd6
```

### b. Send 1000 TOKENB to the recipient

```bash
wallet token send \
    --from Private/HMRHZdPw4pbyPVZHNGrV6K5AA95wACFsHTRST84fr3CF \
    --to Public/88f2zeTgiv9LUthQwPJbrmufb9SiDfmpCs47B7vw6Gd6 \
    --amount 1000
```

### c. Inspect the recipient account

```bash
wallet account get --account-id Public/88f2zeTgiv9LUthQwPJbrmufb9SiDfmpCs47B7vw6Gd6

# Output:
Token program holding record
{"account_type":"Token holding","definition_id":"GQ3C8rbprTtQUCvkuVBRu3v9wvUvjafCMFqoSPvTEVii","balance":1000}
```
