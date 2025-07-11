//! CLI interface to allow regex based file searching and renaming
//! This is just designed for my personal needs and functionality and ergonomics only added as needed.

pub mod error;
pub mod logging;

use clap::Parser;
use error::Result;
use owo_colors::OwoColorize;
use regex::Regex;
use walkdir::WalkDir;

/// Filename Find and (optionally) Replace using Rust Regex Syntax.
///
/// Files are *only* renamed if a `--rep(lace)` argument is provided AND `-p/--preview` is *not* provided.
#[derive(Parser, Debug)]
#[cfg_attr(test, derive(Clone))] // TODO: Remove Clone when CLI and lib structs are separated
#[command(version, about, long_about)]
pub struct Args {
        /// (Rust flavor) regex to search filenames with.
        regex: String,

        /// Replacement string for regex matches. Use `$1` or `${1}`, etc. to reference capture groups.
        #[arg(long = "rep")]
        replacement: Option<String>,

        /// Recurse into child directories.
        #[arg(short, long)]
        recurse: bool,

        /// Show replacements that would occur, but don't rename files.
        #[arg(short, long)]
        preview: bool,
}

/// Application code.  (main in lib.rs)
#[tracing::instrument]
pub fn app(args: &Args) -> Result<()> {
        let re = Regex::new(&args.regex)?;

        if let Some(replacement) = &args.replacement {
                check_for_common_syntax_error(replacement)?;
        }
        let walkable_space = walkdir_build_with_depths(args.recurse);
        core_process_loop(walkable_space, &re, args)
}

/// Walks a WalkDir, handles errors, prints matches, optionally executes
///
/// # Note 1, single-purpose violation:
/// Breaking this function into smaller pieces would create indirection and complexity.
/// For very little benefit given the brevity of the code and the linear logic chain at work.
/// (this does come at the cost of a somewhat ambiguous function name :shrug:)
///
/// # Note 2, loop vs iterator choice:
/// Would be charming as an iterator.  Perhaps using itertools `map_ok` to transform
/// elements passing successive guards.  And then using raw error messages to generate logs.
/// Or `filter_map` with inspects to create similar behavior (and hope compiler notices the double checking of Result & Options).
/// BUT: while charming, the lack of shared scope makes passing references along past multiple
/// guards quite awkward.  And the workarounds end up being deeply nested and more verbose
/// without any clear benefit.
#[tracing::instrument]
fn core_process_loop(walkable_space: WalkDir, re: &Regex, args: &Args) -> Result<()> {
        let rep = &args.replacement;
        let is_test_run = args.preview;
        let mut num_matches: u64 = 0;

        for entry in walkable_space {
                // Guard: walk errors (e.g. loop encountered)
                let Ok(entry) = entry else {
                        tracing::error!("Error encountered while walking dir: {:?}", entry);
                        continue;
                };
                // Guard: entry~>path~>pathentry.path().'s_file_name
                let entry = entry.path();
                let parent = entry
                        .parent()
                        .expect("all entries should have parents due to WalkDir min_depth=1");
                let Some(filename) = entry.file_name() else {
                        tracing::error!("Leaf neither file nor directory: {:?}", entry);
                        continue;
                };
                // Guard: path's_file_name~>str errors (e.g. non-utf8 paths)
                let Some(filename) = filename.to_str() else {
                        tracing::error!("Entry path could not convert to a string: {:?}", filename);
                        continue;
                };
                // Guard: no regex match
                // PERF: repetitive with replaces...
                let Some(_) = re.find(filename) else {
                        tracing::trace!("No Match for Entry: {:?}", filename);
                        continue;
                };
                num_matches += 1;
                // Guard: no replacement
                let Some(rep) = rep else {
                        println!(
                                "Match found: {}/{}",
                                parent.to_string_lossy().blue(),
                                &filename.black().bold().on_green()
                        );
                        continue;
                };
                let new_filename = re.replace(filename, rep);
                // Guard: --test-run
                if is_test_run {
                        println!(
                                "--test-run mapping: {}/{} ~~> {}",
                                parent.to_string_lossy().blue(),
                                &filename.black().bold().on_green(),
                                &new_filename.red().bold().on_blue()
                        );
                        continue;
                }
                println!(
                        "Renaming: {}/{} ~~> {}",
                        parent.to_string_lossy().blue(),
                        &filename.black().bold().on_green(),
                        &new_filename.red().bold().on_blue()
                );
                std::fs::rename(entry, entry.with_file_name(new_filename.as_ref()))?;
                // std::fs::rename(entry, new_filename.as_ref())?;
        }
        println!("Total matches: {}", num_matches.cyan());
        Ok(())
}

/// Guard: Flagging unintended syntax
///
/// Checks replacement string for capture references making a common syntax error:
/// A bare reference number followed by chars that would be combined with it and read as a name
///
/// e.g. `$1abc` will be parsed as ($1abc) NOT ($1)(abc) -- `${1}abc` is proper syntax
#[tracing::instrument]
fn check_for_common_syntax_error(rep_arg: &str) -> Result<()> {
        const RE_SYNTAX_WARN: &str = r"(\$\d)[^\d\$\s]+";

        let re_check = Regex::new(RE_SYNTAX_WARN).expect("valid, static regex");
        if let Some(cap) = re_check.captures(rep_arg) {
                tracing::warn!(
                        "\nWarning:\ncapture reference `{}` is being read as `{}`\nIf this is not intended use: `${{_}}...` instead.",
                        cap[1].to_string().blue(),
                        cap[0].to_string().red()
                );
                return Err("Ambiguous replacement syntax".into());
        }
        Ok(())
}

/// Build a WalkDir object with depth limits based information passed in
#[tracing::instrument]
fn walkdir_build_with_depths(does_recurse: bool) -> WalkDir {
        match does_recurse {
                true => {
                        tracing::debug!("Recursable WalkDir");
                        WalkDir::new(".").contents_first(true).min_depth(1)
                }
                false => {
                        tracing::debug!("non-recursing (shallow) WalkDir");
                        WalkDir::new(".").contents_first(true).min_depth(1).max_depth(1)
                }
        }
}

/// /////////////////////////////////////////////////////////////////////////////////////// //
/// /////////////                 TESTS - lib.rs                             ////////////// //
/// /////////////////////////////////////////////////////////////////////////////////////// //
#[cfg(test)]
pub mod test_pub_utilities {
        use std::{
                fs::{self, File},
                sync::{Mutex, OnceLock},
        };

        use tempfile::TempDir;

        use super::*;

        pub type Result<T> = core::result::Result<T, Error>;
        pub type Error = Box<dyn std::error::Error>;

        /// Forces serialization within a process by running code under a global mutex.
        ///
        /// # Local Usecase:
        /// The 'working directory' is a global state within a process.  (This is an issue
        /// baked into the design of all the major OSes.)
        /// This means that working directory manipulation and reading within tests is *not* thread-safe.
        /// This function allows us to force in-process serialization of working directory access.
        ///
        /// # Design comment:
        /// While the use of a global mutex code executor within an otherwise relatively simple
        /// test suite may seem profligate. (e.g. vs simply running `cargo test` with `-- --test-threads 1`
        /// or using `cargo nextest`, which process separate tests).  The intrinsic global (mutable)
        /// resource character of the working directory should be called out (and ideally dealt with)
        ///  in the region of the code that has to work with it.
        pub fn utility_with_global_mutex<F, R>(f: F) -> R
        where
                F: FnOnce() -> R,
        {
                static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
                let lock = LOCK.get_or_init(|| Mutex::new(()));
                let _guard = lock.lock().unwrap();
                f()
        }

        /// Generate a fixed, populated temporary directory.
        ///
        /// Lib/close note:
        /// TempDirs *are* closed on drop, however errors are not reported by the drop-close. (this is a limitation of `drop()`)
        /// In practice there is little need to check here.  This utility does bubble up creation errors and new TempDirs should have a randimized prefix to make collisions unlikely.
        /// There may be certain cases (particularly on windows machines) where checking is desired.  It can be done as part of manual close with:
        /// ```rust
        /// temp_dir.close()?;
        /// ```
        /// At present, and likely in future, there will be no need for this though.
        ///
        ///
        /// dir_structure:
        /// ```md
        ///   - root/
        ///   - root/file_0a.txt
        ///   - root/file_0b.txt
        ///   - root/file_0c.txt
        ///
        ///   - root/dir_1/
        ///   - root/dir_1/dir_11/
        ///   - root/dir_1/dir_11/dir_111/
        ///   - root/dir_1/file_1a.txt
        ///   - root/dir_1/dir_11/file_11a.txt
        ///   - root/dir_1/dir_11/dir_111/file_111a.txt
        ///
        ///   - root/dir_2/dir_21/
        ///   - root/dir_2/dir_21/dir_211/
        /// ```
        pub fn utility_test_dir_gen() -> Result<TempDir> {
                let dir_root = TempDir::new()?;
                File::create(dir_root.path().join("file_0a.txt"))?;
                File::create(dir_root.path().join("file_0b.txt"))?;
                File::create(dir_root.path().join("file_0c.txt"))?;

                let dir_1 = dir_root.path().join("dir_1");
                let dir_11 = dir_1.join("dir_11");
                let dir_111 = dir_11.join("dir_111");
                fs::create_dir(&dir_1)?;
                fs::create_dir(&dir_11)?;
                fs::create_dir(&dir_111)?;
                File::create(dir_1.join("file_1a.txt"))?;
                File::create(dir_11.join("file_11a.txt"))?;
                File::create(dir_111.join("file_111a.txt"))?;

                let dir_2 = dir_root.path().join("dir_2");
                let dir_21 = dir_2.join("dir_21");
                let dir_211 = dir_21.join("dir_211");
                fs::create_dir(&dir_2)?;
                fs::create_dir(&dir_21)?;
                fs::create_dir(&dir_211)?;

                Ok(dir_root)
        }

        /// Utility function to collect directory state for comparison
        pub fn utility_collect_directory_state(path: &str) -> Result<Vec<std::path::PathBuf>> {
                let mut entries = Vec::new();
                for entry in WalkDir::new(path).contents_first(true) {
                        entries.push(entry?.path().to_path_buf());
                }
                Ok(entries)
        }
}

#[cfg(test)]
pub mod tests_manual {

        use test_log::test;

        use super::*;
        use crate::test_pub_utilities::{
                utility_collect_directory_state, utility_test_dir_gen, utility_with_global_mutex,
        };

        pub type Result<T> = core::result::Result<T, Error>;
        pub type Error = Box<dyn std::error::Error>;

        // Test the app() function
        // Test the core_process_loop() function

        /// Test the check_for_common_syntax_error() function
        #[test]
        fn test_check_for_common_syntax_error() {
                let test_cases = vec![
                        ("$1abc", true),
                        ("${1}abc", false),
                        //
                        ("$1a", true),
                        ("${1}a", false),
                        //
                        ("$1", false),
                        ("${1}", false),
                        //
                        ("$1 ", false),
                        ("${1} ", false),
                        //
                        ("${1} abc ", false),
                        ("$1 abc ", false),
                        //
                        ("$1abc$2", true),
                        ("${1}abc$2", false),
                        //
                        ("$1abc$2def", true),
                        ("${1}abc$2def", true),
                        ("$1abc${2}def", true),
                        ("${1}abc${2}def", false),
                        //
                        ("${1} $2", false),
                        ("$1$2 ", false),
                ];
                for (input, expect_error) in test_cases {
                        let result = check_for_common_syntax_error(input);
                        match (result.is_err(), expect_error) {
                                (true, true) => continue,
                                (false, false) => continue,
                                (true, false) => panic!("Expected no error for input: {}", input),
                                (false, true) => panic!("Expected an error for input: {}", input),
                        }
                }
        }

        /// Flat, iterative change of file names.
        ///
        /// # Warning:
        /// This test manipulates the working directory manipulation (which is a process-wide global state).
        /// Code execution is controlled by a global mutex to make this function thread-safe.
        #[test]
        fn test_app_with_norecursion() -> Result<()> {
                utility_with_global_mutex(|| {
                        let temp_dir = utility_test_dir_gen()?;
                        std::env::set_current_dir(temp_dir.path())?;

                        // run fresh
                        let args = Args {
                                regex: "(file_.*)".to_string(),
                                replacement: Some("changed-${1}".to_string()),
                                recurse: false,
                                preview: false,
                        };
                        app(&args)?;
                        println!("temp: {:?}", temp_dir);

                        assert!(temp_dir.path().join("changed-file_0a.txt").exists());
                        assert!(temp_dir.path().join("changed-file_0b.txt").exists());
                        assert!(temp_dir.path().join("changed-file_0c.txt").exists());

                        // run on changed
                        let args = Args {
                                regex: "(file_.*)".to_string(),
                                replacement: Some("changed-${1}".to_string()),
                                recurse: false,
                                preview: false,
                        };
                        app(&args)?;
                        println!("temp: {:?}", temp_dir);

                        assert!(temp_dir.path().join("changed-changed-file_0a.txt").exists());
                        assert!(temp_dir.path().join("changed-changed-file_0b.txt").exists());
                        assert!(temp_dir.path().join("changed-changed-file_0c.txt").exists());

                        Ok(())
                })
        }

        /// Recursive, iterative change of file and directory names.
        ///
        /// # Warning:
        /// This test manipulates the working directory manipulation (which is a process-wide global state).
        /// Code execution is controlled by a global mutex to make this function thread-safe.
        #[test]
        fn test_app_with_yesrecursion() -> Result<()> {
                utility_with_global_mutex(|| {
                        let temp_dir = utility_test_dir_gen()?;
                        std::env::set_current_dir(temp_dir.path())?;

                        // run fresh
                        let args = Args {
                                regex: "(file.*)".to_string(),
                                replacement: Some("changed-${1}".to_string()),
                                recurse: true,
                                preview: false,
                        };
                        app(&args)?;
                        println!("temp: {:?}", temp_dir);

                        assert!(temp_dir.path().join("changed-file_0a.txt").exists());
                        assert!(temp_dir.path().join("changed-file_0b.txt").exists());
                        assert!(temp_dir.path().join("changed-file_0c.txt").exists());

                        assert!(temp_dir.path().join("changed-file_0c.txt").exists());
                        assert!(temp_dir.path().join("changed-file_0c.txt").exists());
                        assert!(temp_dir.path().join("dir_1").join("changed-file_1a.txt").exists());
                        assert!(temp_dir
                                .path()
                                .join("dir_1")
                                .join("dir_11")
                                .join("changed-file_11a.txt")
                                .exists());
                        assert!(temp_dir
                                .path()
                                .join("dir_1")
                                .join("dir_11")
                                .join("dir_111")
                                .join("changed-file_111a.txt")
                                .exists());

                        // run against dirs
                        let args = Args {
                                regex: "(dir.*)".to_string(),
                                replacement: Some("changed-${1}".to_string()),
                                recurse: true,
                                preview: false,
                        };
                        app(&args)?;
                        println!("temp: {:?}", temp_dir);

                        assert!(temp_dir.path().join("changed-file_0a.txt").exists());
                        assert!(temp_dir.path().join("changed-file_0b.txt").exists());
                        assert!(temp_dir.path().join("changed-file_0c.txt").exists());

                        assert!(temp_dir.path().join("changed-file_0c.txt").exists());
                        assert!(temp_dir.path().join("changed-file_0c.txt").exists());
                        assert!(temp_dir
                                .path()
                                .join("changed-dir_1")
                                .join("changed-file_1a.txt")
                                .exists());
                        assert!(temp_dir
                                .path()
                                .join("changed-dir_1")
                                .join("changed-dir_11")
                                .join("changed-file_11a.txt")
                                .exists());
                        assert!(temp_dir
                                .path()
                                .join("changed-dir_1")
                                .join("changed-dir_11")
                                .join("changed-dir_111")
                                .join("changed-file_111a.txt")
                                .exists());

                        // run against both
                        let args = Args {
                                regex: r"(\d+)".to_string(),
                                replacement: Some("d${1}".to_string()),
                                recurse: true,
                                preview: false,
                        };
                        app(&args)?;
                        println!("temp: {:?}", temp_dir);

                        assert!(temp_dir.path().join("changed-file_d0a.txt").exists());
                        assert!(temp_dir.path().join("changed-file_d0b.txt").exists());
                        assert!(temp_dir.path().join("changed-file_d0c.txt").exists());

                        assert!(temp_dir.path().join("changed-file_d0c.txt").exists());
                        assert!(temp_dir.path().join("changed-file_d0c.txt").exists());
                        assert!(temp_dir
                                .path()
                                .join("changed-dir_d1")
                                .join("changed-file_d1a.txt")
                                .exists());
                        assert!(temp_dir
                                .path()
                                .join("changed-dir_d1")
                                .join("changed-dir_d11")
                                .join("changed-file_d11a.txt")
                                .exists());
                        assert!(temp_dir
                                .path()
                                .join("changed-dir_d1")
                                .join("changed-dir_d11")
                                .join("changed-dir_d111")
                                .join("changed-file_d111a.txt")
                                .exists());

                        Ok(())
                })
        }

        /// Files are only renamed if preview=false AND replacement=Some AND regex has a match. (i.e. if any of true, None, or no-match occurs then no changes should occur)
        /// We take a a base set of args, validate that they would cause a change, and then apply each
        /// case that should be change blocking, alone, to that base set and verify that no change occurred.
        ///
        /// # Warning:
        /// This test manipulates the working directory manipulation (which is a process-wide global state).
        /// Code execution is controlled by a global mutex to make this function thread-safe.
        #[test]
        fn test_no_change_if_preview_or_norep_or_nomatch() -> Result<()> {
                utility_with_global_mutex(|| {
                        // base config that *should* result in changes
                        let base_args = Args {
                                regex: "(file_.*)".to_string(),
                                replacement: Some("changed-${1}".to_string()),
                                recurse: true,
                                preview: false,
                        };

                        // test 0, preamble: verify that base config *does* cause changes to files/dirs
                        {
                                let temp_dir = utility_test_dir_gen()?;
                                std::env::set_current_dir(temp_dir.path())?;

                                let mut directory_before_state = utility_collect_directory_state(".")?;
                                app(&base_args)?;
                                let mut directory_after_state = utility_collect_directory_state(".")?;

                                directory_before_state.sort();
                                directory_after_state.sort();

                                if directory_before_state == directory_after_state {
                                        tracing::error!(
                                                "PREAMBLE TEST FAILED: base_args should have caused changes but didn't"
                                        );
                                        return Err("Base_args should cause changes but didn't".into());
                                }
                        }

                        // test 1+, main: verify that various states prevent changes to files/dirs
                        let nochange_test_cases = [
                                ("preview_true", Args { preview: true, ..base_args.clone() }),
                                ("replacement_none", Args { replacement: None, ..base_args.clone() }),
                                (
                                        "no_matches",
                                        Args {
                                                regex: "no_match_pattern_xyz".to_string(),
                                                replacement: Some("should_not_be_used".to_string()),
                                                ..base_args.clone()
                                        },
                                ),
                        ];

                        for (test_name, args) in nochange_test_cases {
                                let temp_dir = utility_test_dir_gen()?;
                                std::env::set_current_dir(temp_dir.path())?;

                                let mut directory_before_state = utility_collect_directory_state(".")?;
                                app(&args)?;
                                let mut directory_after_state = utility_collect_directory_state(".")?;

                                directory_before_state.sort();
                                directory_after_state.sort();

                                if directory_before_state != directory_after_state {
                                        tracing::error!(
                                                "NO-CHANGE TEST FAILED: \"{}\" should not have changed directory state, but did",
                                                test_name
                                        );
                                        return Err(format!(
                                                "No-Change test \"{}\" should have resulted in changed directory state, but did",
                                                test_name
                                        )
                                        .into());
                                }
                        }

                        Ok(())
                })
        }

        /// Test invariant: invalid regex should fail early with no directory changes
        ///
        /// This is separate from the main 3 prerequisites (preview=false AND replacement=Some AND regex has a match).
        /// Invalid regex should fail during regex compilation before any filesystem operations occur.
        ///
        /// # Warning:
        /// This test manipulates the working directory manipulation (which is a process-wide global state).
        /// Code execution is controlled by a global mutex to make this function thread-safe.
        #[test]
        fn test_no_changes_if_invalid_regex() -> Result<()> {
                utility_with_global_mutex(|| {
                        // base config that *should* result in changes
                        let base_args = Args {
                                regex: "(file_.*)".to_string(),
                                replacement: Some("changed-${1}".to_string()),
                                recurse: true,
                                preview: false,
                        };

                        // test 0, preamble: verify that base config *does* cause changes to files/dirs
                        {
                                let temp_dir = utility_test_dir_gen()?;
                                std::env::set_current_dir(temp_dir.path())?;

                                let mut directory_before_state = utility_collect_directory_state(".")?;
                                app(&base_args)?;
                                let mut directory_after_state = utility_collect_directory_state(".")?;

                                directory_before_state.sort();
                                directory_after_state.sort();

                                if directory_before_state == directory_after_state {
                                        tracing::error!(
                                                "PREAMBLE TEST FAILED: base_args should have caused changes but didn't"
                                        );
                                        return Err("Base_args should cause changes but didn't".into());
                                }
                        }

                        let temp_dir = utility_test_dir_gen()?;
                        std::env::set_current_dir(temp_dir.path())?;

                        let mut directory_before_state = utility_collect_directory_state(".")?;

                        // contains invalid regex (should fail and not modify filesystem)
                        let invalidregex_args = Args {
                                regex: "[invalid_regex".to_string(), // Missing closing bracket
                                ..base_args.clone()
                        };

                        let result = app(&invalidregex_args);
                        assert!(result.is_err(), "Invalid regex should result in error");

                        // check error returned
                        let error_string = format!("{}", result.unwrap_err());
                        assert!(
                                error_string.contains("regex") || error_string.contains("parse"),
                                "Error should mention regex parsing: {}",
                                error_string
                        );

                        let mut directory_after_state = utility_collect_directory_state(".")?;

                        // check no changes
                        directory_before_state.sort();
                        directory_after_state.sort();
                        assert_eq!(
                                directory_before_state, directory_after_state,
                                "Directory state should be unchanged when regex is invalid"
                        );
                        Ok(())
                })
        }
}

/// # Snapshots with `expect-test`
///
/// ## Control
/// 1. env-var controlling expect-test (snapshot lib) behavior: `UPDATE_EXPECT=1`
/// 2. use *rust-analyzer* lsp **action** to run individual test with update
#[cfg(test)]
pub mod tests_snapshot {
        use expect_test::{Expect, expect};
        use test_log::test;

        use super::*;
        use crate::test_pub_utilities::{
                utility_collect_directory_state, utility_test_dir_gen, utility_with_global_mutex,
        };

        pub type Result<T> = core::result::Result<T, Error>;
        pub type Error = Box<dyn std::error::Error>;

        /// Utility function for snapshot testing: lossly string image of a directory.
        ///
        /// Capture directory paths as strings *lossily* and join via `\n`.
        /// Paths are sorted *prior* to lossy-string conversion.
        fn utility_capture_directory_tree_as_string(path: &str) -> Result<String> {
                let mut entries = utility_collect_directory_state(path)?;
                entries.sort();
                let formatted = entries
                        .iter()
                        .map(|p| p.to_string_lossy().to_string())
                        .collect::<Vec<_>>()
                        .join("\n");
                Ok(formatted)
        }

        /// # (¡dev-xplr!) Snapshot (expect-test) replication of a manual test. (Mostly here for Dev Exploration purposes)
        ///
        /// # Warning:
        /// This test manipulates the working directory manipulation (which is a process-wide global state).
        /// Code execution is controlled by a global mutex to make this function thread-safe.
        #[test]
        fn test_snap_directory_structure_after_rename() -> Result<()> {
                utility_with_global_mutex(|| {
                        let temp_dir = utility_test_dir_gen()?;
                        std::env::set_current_dir(temp_dir.path())?;

                        let args = Args {
                                regex: "(file_.*)".to_string(),
                                replacement: Some("renamed_${1}".to_string()),
                                recurse: false,
                                preview: false,
                        };

                        app(&args)?;
                        let actual = utility_capture_directory_tree_as_string(".")?;
                        let expected = expect![[r#"
                            .
                            ./dir_1
                            ./dir_1/dir_11
                            ./dir_1/dir_11/dir_111
                            ./dir_1/dir_11/dir_111/file_111a.txt
                            ./dir_1/dir_11/file_11a.txt
                            ./dir_1/file_1a.txt
                            ./dir_2
                            ./dir_2/dir_21
                            ./dir_2/dir_21/dir_211
                            ./renamed_file_0a.txt
                            ./renamed_file_0b.txt
                            ./renamed_file_0c.txt"#]];
                        expected.assert_eq(&actual);
                        Ok(())
                })
        }

        /// Snapshot test: error messages for a small sample of bad pre-regex strings
        ///
        /// # Warning:
        /// This test manipulates the working directory manipulation (which is a process-wide global state).
        /// Code execution is controlled by a global mutex to make this function thread-safe.
        #[test]
        fn test_snap_regex_error_messages() -> Result<()> {
                // base config that *should* result in changes
                let base_args = Args {
                        regex: ".*".to_string(),
                        replacement: Some("changed-${1}".to_string()),
                        recurse: true,
                        preview: false,
                };

                let closure_check = |preregex: &str, expected: Expect| -> Result<()> {
                        let args_with_bad_preregex = Args { regex: preregex.to_string(), ..base_args.clone() };

                        let temp_dir = utility_test_dir_gen()?;
                        let actual = utility_with_global_mutex(|| {
                                std::env::set_current_dir(temp_dir.path())?;
                                app(&args_with_bad_preregex)
                        });
                        expected.assert_debug_eq(&actual);
                        Ok(())
                };

                //  "unclosed_bracket"
                closure_check(
                        r"[unclosed",
                        expect![[r#"
                    Err(
                        Syntax(
                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                        regex parse error:
                            [unclosed
                            ^
                        error: unclosed character class
                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                        ),
                    )
                "#]],
                )?;

                //  "empty_named_group"
                closure_check(
                        r"(?P<>)",
                        expect![[r#"
                    Err(
                        Syntax(
                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                        regex parse error:
                            (?P<>)
                                ^
                        error: empty capture group name
                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                        ),
                    )
                "#]],
                )?;

                //  "trailing_backslash"
                closure_check(
                        r"\",
                        expect![[r#"
                    Err(
                        Syntax(
                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                        regex parse error:
                            \
                            ^
                        error: incomplete escape sequence, reached end of pattern prematurely
                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                        ),
                    )
                "#]],
                )?;

                Ok(())
        }

        /// Snapshot test: error messages for a small sample of bad replacement values
        ///
        /// # Warning:
        /// This test manipulates the working directory manipulation (which is a process-wide global state).
        /// Code execution is controlled by a global mutex to make this function thread-safe.
        #[test]
        fn test_snap_rep_error_messages() -> Result<()> {
                const AMBIG_REP_EXAMPLE: &str = r"$1text";
                let args = Args {
                        regex: r".*".to_string(),
                        replacement: Some(AMBIG_REP_EXAMPLE.to_string()),
                        recurse: true,
                        preview: true,
                };
                let temp_dir = utility_test_dir_gen()?;

                let actual = utility_with_global_mutex(|| {
                        std::env::set_current_dir(temp_dir.path())?;
                        app(&args)
                });
                let expected = expect![[r#"
                    Err(
                        "Ambiguous replacement syntax",
                    )
                "#]];
                expected.assert_debug_eq(&actual);

                Ok(())
        }

        // /// Test regex replacement examples snapshot
        // #[test]
        // fn test_snap_replacement_examples() -> Result<()> {
        //         let test_cases = vec![
        //                 ("file_123.txt", r"(\d+)", "num_${1}"),
        //                 ("CamelCase.rs", r"([A-Z])", "_${1}"),
        //                 ("test_file.txt", r"test_", "new_"),
        //         ];

        //         let mut results = Vec::new();
        //         for (input, pattern, replacement) in test_cases {
        //                 let re = Regex::new(pattern)?;
        //                 let result = re.replace(input, replacement);
        //                 results.push(format!("{} -> {}", input, result));
        //         }

        //         let formatted_results = results.join("\n");
        //         assert_snapshot!("replacement_examples", formatted_results);
        //         Ok(())
        // }
}

// #[cfg(test)]
// pub mod tests_random_sample {
//         use quickcheck::{Arbitrary, Gen, TestResult};
//         use quickcheck_macros::quickcheck;
//         use test_log::test;

//         use super::*;
//         use crate::test_pub_utilities::{
//                 utility_collect_directory_state, utility_test_dir_gen, utility_with_global_mutex,
//         };

//         pub type Result<T> = core::result::Result<T, Error>;
//         pub type Error = Box<dyn std::error::Error>;

//         /// Custom generator for known-good regex strings
//         #[derive(Debug, Clone)]
//         struct ValidRegexString(String);

//         impl Arbitrary for ValidRegexString {
//                 fn arbitrary(g: &mut Gen) -> Self {
//                         let patterns =
//                                 ["file.*", r"\d+", "[a-z]+", ".*\\.txt", "(test|spec)", "[A-Za-z_][A-Za-z0-9_]*"];
//                         let idx = usize::arbitrary(g) % patterns.len();
//                         ValidRegexString(patterns[idx].to_string())
//                 }
//         }

//         /// Test that preview=true never changes filesystem regardless of other args
//         #[quickcheck]
//         fn test_qc_preview_never_changes_filesystem(
//                 regex: ValidRegexString,
//                 replacement: Option<String>,
//                 recurse: bool,
//         ) -> TestResult {
//                 let result = utility_with_global_mutex(|| -> Result<bool> {
//                         let temp_dir = utility_test_dir_gen()?;
//                         std::env::set_current_dir(temp_dir.path())?;

//                         let mut before_state = utility_collect_directory_state(".")?;

//                         let args = Args {
//                                 regex: regex.0,
//                                 replacement,
//                                 recurse,
//                                 preview: true, // This should prevent all changes
//                         };

//                         let _ = app(&args); // Ignore result, just check filesystem state

//                         let mut after_state = utility_collect_directory_state(".")?;

//                         before_state.sort();
//                         after_state.sort();

//                         Ok(before_state == after_state)
//                 });

//                 match result {
//                         Ok(unchanged) => TestResult::from_bool(unchanged),
//                         Err(_) => TestResult::discard(), // Discard invalid test cases
//                 }
//         }

//         /// Test that replacement=None never changes filesystem
//         #[quickcheck]
//         fn test_qc_no_change_if_norep(regex: ValidRegexString, recurse: bool) -> TestResult {
//                 let result = utility_with_global_mutex(|| -> Result<bool> {
//                         let temp_dir = utility_test_dir_gen()?;
//                         std::env::set_current_dir(temp_dir.path())?;

//                         let mut before_state = utility_collect_directory_state(".")?;

//                         let args = Args {
//                                 regex: regex.0,
//                                 replacement: None, // This should prevent all changes
//                                 recurse,
//                                 preview: false,
//                         };

//                         let _ = app(&args); // Ignore result, just check filesystem state

//                         let mut after_state = utility_collect_directory_state(".")?;

//                         before_state.sort();
//                         after_state.sort();

//                         Ok(before_state == after_state)
//                 });

//                 match result {
//                         Ok(unchanged) => TestResult::from_bool(unchanged),
//                         Err(_) => TestResult::discard(),
//                 }
//         }

//         /// Test replacement behavior using built-in PathBuf generator
//         #[quickcheck]
//         fn test_qc_replacement_uses_real_filenames(
//                 path: std::path::PathBuf,
//                 regex: ValidRegexString,
//                 replacement: String,
//         ) -> TestResult {
//                 use regex::Regex;

//                 // Extract filename from generated path
//                 let filename = match path.file_name().and_then(|n| n.to_str()) {
//                         Some(f) if !f.is_empty() => f,
//                         _ => return TestResult::discard(),
//                 };

//                 let re = match Regex::new(&regex.0) {
//                         Ok(re) => re,
//                         Err(_) => return TestResult::discard(),
//                 };

//                 // Test that the same input produces the same output (determinism)
//                 let result1 = re.replace(filename, &replacement);
//                 let result2 = re.replace(filename, &replacement);

//                 TestResult::from_bool(result1 == result2)
//         }

//         /// Test no changes when regex doesn't match anything
//         #[quickcheck]
//         fn test_qc_no_change_if_no_matches(replacement: Option<String>, recurse: bool) -> TestResult {
//                 let result = utility_with_global_mutex(|| -> Result<bool> {
//                         let temp_dir = utility_test_dir_gen()?;
//                         std::env::set_current_dir(temp_dir.path())?;

//                         let mut before_state = utility_collect_directory_state(".")?;

//                         let args = Args {
//                                 regex: "definitely_wont_match_anything_xyz123".to_string(),
//                                 replacement,
//                                 recurse,
//                                 preview: false,
//                         };

//                         let _ = app(&args); // Ignore result, just check filesystem state

//                         let mut after_state = utility_collect_directory_state(".")?;

//                         before_state.sort();
//                         after_state.sort();

//                         Ok(before_state == after_state)
//                 });

//                 match result {
//                         Ok(unchanged) => TestResult::from_bool(unchanged),
//                         Err(_) => TestResult::discard(),
//                 }
//         }
// }
