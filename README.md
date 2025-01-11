# Common Parallel Rust

## Gist
- This repo exists to support synchronizing boilerplate elements across rust repos.
  - It houses branches designed for use with `git merge --allow-unrelated-histories`. ('parallel merge')
  - `main` is **NOT** designed for this purpose
    - `main` is a *living repository* -- which allows the impact of files changes to be directly observed
      - experience with templating systems (including one of my own) have shown that a 'template' that cannot be run and use normal tests and code verification mechanisms creates a fair bit of toil.
  - All of the branches for parallel merge are by-file subsets of main.
  - Branches:
    - `simple_config`
      - Rust & 3rd party config files that should see relatively little need for repo-specific changes
    - `config_with_just`
      - simple_config + a justfile, which is likely to see repo-specific changes and *and* should have any merges manually reviewed.
      - if more repo-scripting moves to cargo xtask we may also add a version of this with xtask files.  (until then manual synch is expected)
    - `workspace_init`
      - this is close to `main`, and could be a living repo in its own right.  It is not intended to be used to upstream changes for synchronization.  It's merely an alternative to repo-templating that takes advatnage of the livign repository approach already in use here.

## Merging Code
```zsh
REMOTE_REPO='git@github.com:dream-dasher/common_parallel_rust.git'
ALIAS_OF_REMOTE='common_par'
REMOTE_BRANCH_TO_MERGE='workspace_init|config_with_just|simple_config'
git remote add $ALIAS_OF_REMOTE $REMOTE_REPO
git fetch $LOCAL_ALIAS
git merge --allow-unrelated-histories $ALIAS_OF_REMOTE/$REMOTE_BRANCH_TO_MERGE
```
`(opt: --strategy-option theirs)`
