# LEZ documentation

| Directory | What it holds |
|---|---|
| [`lez-guide/`](lez-guide/src/introduction.md) | The LEZ guide, ordered by depth: understand, use, build, integrate, reference and internals. Documents the actor interface, which ships in `v0.4.0`. Start here, and read [Which interface you are writing for](lez-guide/src/understand/which-interface.md) first if you are writing a program. |
| [`program-development-book/`](program-development-book/src/introduction.md) | The program development book, documenting the plan/apply interface as released, with a catalog of worked designs. |
| [`LEZ testnet v0.1 tutorials/`](LEZ%20testnet%20v0.1%20tutorials/) | Wallet setup, token transfer and Keycard, against the public testnet. |
| [`benchmarks/`](benchmarks/) | Proving and execution cycle counts, client-side crypto timings, and per-block message sizes. |
| [`metrics/`](metrics/metrics.md) | How metrics are defined, named and turned into dashboards. |
| `ci/` | `check_book_paths.py`, which fails CI when a book cites a repository path that no longer exists, has a dead intra-book link, or includes a file that is not there. `render_diagrams.py`, which rebuilds a book's committed SVGs from its `diagrams/specs.py`: run `python3 docs/ci/render_diagrams.py docs/<book>` after editing a spec, since CI fails if they drift. |

Both books are mdbooks. From the repository root, build either one with `mdbook build docs/<book>` and open `docs/<book>/book/index.html`, or serve it with `mdbook serve docs/<book>`.

The two books document different program interfaces, and only plan/apply is in a release.
