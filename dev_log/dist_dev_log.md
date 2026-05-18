# dev_log `dist` branch

### Goal
Simplifying generation of code that can be easily consumed by 3rd parties.
in particular:
- generating binaries for various architectures
- generating binaries downloadable by package managers (just **homebrew**, rn)

### Intermediate needs
- more info in `Cargo.toml` file (and hence in coming template)
- considerations regarding flexible workspace setup (re: coming template)
    - will probably be simplest to just always start in a virtual workspace, for template
    - right now we're just going to use the current templating system
- fetching (and way of safe storing) secrets related to homebrew & github
    - deets tbd

### Active Questions
- Reqs to get homebrew push working
    - (I've got one homebrew available project, but would have to review the steps for it; as I do between every period of updates of it)
    - some secrets to/from github will also be needed
    - **ANSWER**: [cargo-dist link](https://opensource.axo.dev/cargo-dist/book/installers/homebrew.html), TLDR: make a tap '<owner>/Homebrew-<repo>' and use repo-scoped (!!) github personal token to let remote CI update it.
        - **WARNING** "repo-scoped" is not scoped to a single repo, but to repos in general.  There's currently a lack of granularity in github auth options
          - **NOTE** "new fine-grained personal access token"s are available; will try that.
        - note: the tap system is just a way of pointing at some specs that say how to install stuff and where it is (semi-helpful comments on [taps generally](https://docs.brew.sh/Taps))
    - Note: token can be regenerated in `Settings > Developer settings > Personal access tokens > Tokens (classic)` 
      - and then the new code re-added to launching repo at `<repo> >Settings > Secrets & Variables > Actions`
- Private homebrew: e.g. for an org, workable?
- Process for specifying packages/crates (not the same thing, formally) to publish in a multi-crate workspace (e.g. cli vs egui code)
- Changelog options (and decisions)


### Links
- Tool Docs: [axo.dev - cargo-dist docs](https://opensource.axo.dev/cargo-dist/book/introduction.html)
- Tool Github: [axodotdev / cargo-dist](https://github.com/axodotdev/cargo-dist)

### Install:
```shell
cargo install cargo-dist --locked
```

### Repo Setup
- NOTE: this can *and is intended* to be re-run.  Past choices are perseved (as defaults).  
- **WARNING** : this adds code (so to speak) to the `Cargo.toml` and it will inject itself *above* EoF comments.  This, for example, will move commented dev-dependencies away from their intended section and throw them somewhere else.  (TODO: make PR/issue -- they may desire the behavior, if the comments are meant to be EoD comments *per se*)
```shell
cargo dist init
```

### example dist-triggering git commands
```shell
TEMP_VERSION="0.2.0"
git add .
git commit -m "release: ${TEMP_VERSION}"
git tag "v${TEMP_VERSION}"
git push
git push --tags
```

### Other Commands
- build for *current* platform: `cargo dist build`
    - only local target, and it *is* built (unsure what happens if local isn't a target :shrug:)
- check what remote will build: `cargo dist plan`
    - all targets, but nothing actually done
