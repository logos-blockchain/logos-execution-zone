# Module Release Runbook

This document explains how to release LEZ-related modules on Logos Basecamp.

## I. Initialize Logos Modules Repo

All offical modules live as submodules under [`logos-modules-release`](https://github.com/logos-co/logos-modules-release). You should have cloned it locally, and be at the latest `main` branch.

```sh
cd logos-modules-release && git checkout main && git pull
git submodule update --init --recursive
```

## II. Updating Modules

There are 4 repositories that depend on LEZ:

```ml
logos-execution-zone
|_ logos-execution-zone-module
| |_ logos-execution-zone-wallet-ui
|
|_ lez-indexer-module
  |_ lez-explorer-ui
```

As shown by the (reverse) dependency graph above, modules depend on this repo, and UIs depend on those modules.

Update the module / UI as follows:

- If a dependent version is updated and is using a difference branch / tag, change it's pinned ref in `flake.nix` and then do `flake nix update <module-name>`. For example:

```diff
- logos-execution-zone.url = "github:logos-blockchain/logos-execution-zone?ref=main
+ logos-execution-zone.url = "github:logos-blockchain/logos-execution-zone?ref=some-other-branch
```

- If you are still using `main` on that repo, simply do `flake nix update <module-name>` and you will actually see that `flake.lock` is updated to the latest commit.

- Do your code updates as usual. When you are done, make sure that you stage the changes, otherwise `nix` will not see them!

- Bump the `version` field in `metadata.json`. That is the version number seen by Logos Basecamp!
  - Some modules may serve the version number as a static string as well outside of `metadata.json`, do a CTRL+F to find those if needed.
  - You can keep the version as-is if you want to, but then when building a release you have to click <kbd>Force build</kbd>. More on this later.

- Once you are done with the updates, always check with `nix build` to see that everything compiles. This may take a while depending on the module.

> [!TIP]
>
> For the UI modules, you can further do `nix run .` to run a standalone application. After `nix build` these do not take that much time, so it's safer to actually see that UI runs like this as well.

## III. Updating Submodules in Logos Modules Repo

> [!NOTE]
>
> The steps here below are very easy with VsCode Source Control view, but you can use the `git` commands as well if you want to.

Now we would like to bump submodules, and create a PR to `main` with these bumped submodules.

Create a branch for this new release, e.g. `username/releases-for-0.3.0`.

```sh
git checkout main && git pull
git checkout -b <branchName>
```

Bump each submodule that we want to update:

```sh
cd submodules/<moduleName> && git checkout origin/<branchName> && cd ..
```

Stake all submodules:

```sh
git add submodules/<moduleName> # ...
```

Now commit and push:

```sh
git commit -m "chore: bump <modules> for <date/tag> release"
git push -u origin HEAD
```

You can now create a PR for this branch. You can use web-viewer or terminal for this. Make sure to select `logos-co/logos-modules-release` as the target repo, since this is actually a template repo and there are several forks out there.

```sh
gh pr create --repo logos-co/logos-modules-release --fill
```

> [!TIP]
>
> To be extra safe, you can re-pull main and rebase if needed before merging. A stale branch can actually revert someone else's submodule pointers.

## IV. Merge & Release

After PR is approved (or not, depending on urgency) and merged, you can create a new release.

- Open the actions tab <https://github.com/logos-co/logos-modules-release/actions>
- Select `Release <module>` from the left sidebar.
- Click on `Run workflow`.
  - Notice that branch is `main` (which is where we merged to); for experimental / quick-fix releases you can actually point your own branch for these too. But let's keep it as is.
  - <kbd>Force build</kbd> check box is important: if the version did NOT change for the module, you MUST check this box, otherwise the release will not go through.

That's it! Once the actions are finished, you will be able to see the latest releases on Logos Basecamp package manager.

> [!NOTE]
>
> Some modules fail the Windows release at the time of writing, that is normal, a missing packages.x86_64-windows fails only that leg.
