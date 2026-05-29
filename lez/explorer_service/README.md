# LEE Blockchain Explorer

A web-based UI for exploring the blockchain state, built with Rust and Leptos framework.

## Features

- **Main Page**: Search for blocks, transactions, or accounts by hash/ID. View recent blocks.
- **Block Page**: View detailed block information and all transactions within a block.
- **Transaction Page**: View transaction details including type, accounts involved, and proofs.
- **Account Page**: View account state and transaction history.

## Architecture

- **Framework**: Leptos 0.8 with SSR (Server-Side Rendering) and hydration
- **Data Source**: Indexer Service JSON-RPC API
- **Components**: Reusable BlockPreview, TransactionPreview, and AccountPreview components
- **Styling**: Custom CSS with responsive design

## Development

### Prerequisites

- Rust (stable or nightly)
- `cargo-leptos` tool: `cargo install cargo-leptos`
- Running indexer service at `http://localhost:8080/rpc` (or configure via `INDEXER_RPC_URL`)

### Build and Run

```bash
# Development mode (with hot-reload)
cargo leptos watch

# Production build
cargo leptos build --release

# Run production build
cargo leptos serve --release
```

The explorer will be available at `http://localhost:3000` by default.

### Configuration

Set the `INDEXER_RPC_URL` environment variable to point to your indexer service:

```bash
export INDEXER_RPC_URL=http://localhost:8080/rpc
cargo leptos watch
```

## Features

### Search

The search bar supports:
- Block IDs (numeric)
- Block hashes (64-character hex)
- Transaction hashes (64-character hex)
- Account IDs (64-character hex)

### Real-time Updates

The main page loads recent blocks and can be extended to subscribe to new blocks via WebSocket.

### Responsive Design

The UI is mobile-friendly and adapts to different screen sizes.

## License

See LICENSE file in the repository root.
