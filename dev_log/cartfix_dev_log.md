# dev_log - `cartfix` branch

- investigating why `cargo nextest` and `cargo test -- test-threads 1` successfully run test, but `cargo test` does not.
    - Separate tests are sharing temp directories and failing (for `cargo test`)
    - `TempDir::new()` should (confirmed: does) generate unique root names for each test
    - `cargo nextest` nominally runs tests in parallel, but does not seem to have the same issues 
    
- Apparent cause: 
    ```rust
    std::env::set_current_dir(&temp_dir.path())?;
    ```
    is the culprit.  With *working directory being shared state*.
    - `cargo test` runs tests in separate **threads**, but *not* separate **processes**.
    - `cargo nextest` runs tests in separate **processes**, presumably why it's not erroring
    - NOTE: while the working_directory determined by ` std::env::set_current_dir` is a shared variable (~'global state'), it is not operating on an ENV_var (which I originally inferred)
    - Reading quite a bit by people working on or with cargo test team and nextest the cargo-test behavior is considered suboptimal in various ways.  However, at least in part for understandable backwards compatibility reasons the behavior is difficult to change.
    
    - Option_1: keep using `-- --test-threads 1`
    - Option_2: mutex guard on dir setter. (some prefer, but this seems like ugly over engineering)
    - Option_3: spawn a process within the test functions
    - Option_4: just commit to nextest and make that clear in repo

- Some refs:
    - [rust-lang discussion](https://users.rust-lang.org/t/env-set-current-dir-in-integration-tests-for-command-line-app/36143)
    - separate, on bringing tests *together* into a process on nextest[github](https://github.com/nextest-rs/nextest/issues/27)
    - some comments from epage on test vs nextest [blog](https://epage.github.io/blog/2023/06/iterating-on-test/)
