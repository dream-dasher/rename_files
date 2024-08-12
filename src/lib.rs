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
/// Files are only renamed if a `--rep(lace)` argument is provided AND `--test-run` or `-t` is *not* provided.  
#[derive(Parser, Debug)]
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
                let parent = entry.parent().expect("all entries should have parents due to WalkDir min_depth=1");
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
                        println!("Match found: {}/{}",
                                 parent.to_string_lossy().blue(),
                                 &filename.black().bold().on_green());
                        continue;
                };
                let new_filename = re.replace(filename, rep);
                // Guard: --test-run
                if is_test_run {
                        println!("--test-run mapping: {}/{} ~~> {}",
                                 parent.to_string_lossy().blue(),
                                 &filename.black().bold().on_green(),
                                 &new_filename.red().bold().on_blue());
                        continue;
                }
                println!("Renaming: {}/{} ~~> {}",
                         parent.to_string_lossy().blue(),
                         &filename.black().bold().on_green(),
                         &new_filename.red().bold().on_blue());
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
                tracing::warn!("\nWarning:\ncapture reference `{}` is being read as `{}`\nIf this is not intended use: `${{_}}...` instead.",
                               cap[1].to_string().blue(),
                               cap[0].to_string().red());
                return Err("Ambiguous replacement syntax".into());
        }
        Ok(())
}

/// Build a WalkDir object with depth limits based information passed in
#[tracing::instrument]
fn walkdir_build_with_depths(does_recurse: bool) -> WalkDir {
        if does_recurse {
                tracing::debug!("Recursable WalkDir");
                return WalkDir::new(".").contents_first(true).min_depth(1);
        }

        tracing::debug!("non-recursing (shallow) WalkDir");
        WalkDir::new(".").contents_first(true).min_depth(1).max_depth(1)
}

/// /////////////////////////////////////////////////////////////////////////////////////// //
/// /////////////                 TESTS - lib.rs                             ////////////// //
/// /////////////////////////////////////////////////////////////////////////////////////// //
#[cfg(test)]
pub mod tests {
        use std::{fs::{self, File},
                  sync::{Mutex, OnceLock}};

        use tempfile::TempDir;
        use test_log::test;

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
        fn utility_with_global_mutex<F, R>(f: F) -> R
                where F: FnOnce() -> R {
                static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
                let lock = LOCK.get_or_init(|| Mutex::new(()));
                let _guard = lock.lock().unwrap();
                f()
        }

        /// Generate a fixed, populated temporary directory.
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
        fn utility_test_dir_gen() -> Result<TempDir> {
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

        // Test the app() function
        // Test the core_process_loop() function

        /// Test the check_for_common_syntax_error() function
        #[test]
        fn test_check_for_common_syntax_error() {
                let test_cases = vec![("$1abc", true),
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
                                      ("$1$2 ", false)];
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
                        std::env::set_current_dir(&temp_dir.path())?;

                        // run fresh
                        let args = Args { regex:       "(file_.*)".to_string(),
                                          replacement: Some("changed-${1}".to_string()),
                                          recurse:     false,
                                          preview:     false, };
                        app(&args)?;
                        println!("temp: {:?}", temp_dir);

                        assert!(temp_dir.path().join("changed-file_0a.txt").exists());
                        assert!(temp_dir.path().join("changed-file_0b.txt").exists());
                        assert!(temp_dir.path().join("changed-file_0c.txt").exists());

                        // run on changed
                        let args = Args { regex:       "(file_.*)".to_string(),
                                          replacement: Some("changed-${1}".to_string()),
                                          recurse:     false,
                                          preview:     false, };
                        app(&args)?;
                        println!("temp: {:?}", temp_dir);

                        assert!(temp_dir.path().join("changed-changed-file_0a.txt").exists());
                        assert!(temp_dir.path().join("changed-changed-file_0b.txt").exists());
                        assert!(temp_dir.path().join("changed-changed-file_0c.txt").exists());

                        temp_dir.close()?;
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
                        std::env::set_current_dir(&temp_dir.path())?;

                        // run fresh
                        let args = Args { regex:       "(file.*)".to_string(),
                                          replacement: Some("changed-${1}".to_string()),
                                          recurse:     true,
                                          preview:     false, };
                        app(&args)?;
                        println!("temp: {:?}", temp_dir);

                        assert!(temp_dir.path().join("changed-file_0a.txt").exists());
                        assert!(temp_dir.path().join("changed-file_0b.txt").exists());
                        assert!(temp_dir.path().join("changed-file_0c.txt").exists());

                        assert!(temp_dir.path().join("changed-file_0c.txt").exists());
                        assert!(temp_dir.path().join("changed-file_0c.txt").exists());
                        assert!(temp_dir.path().join("dir_1").join("changed-file_1a.txt").exists());
                        assert!(temp_dir.path().join("dir_1").join("dir_11").join("changed-file_11a.txt").exists());
                        assert!(temp_dir.path()
                                        .join("dir_1")
                                        .join("dir_11")
                                        .join("dir_111")
                                        .join("changed-file_111a.txt")
                                        .exists());

                        // run against dirs
                        let args = Args { regex:       "(dir.*)".to_string(),
                                          replacement: Some("changed-${1}".to_string()),
                                          recurse:     true,
                                          preview:     false, };
                        app(&args)?;
                        println!("temp: {:?}", temp_dir);

                        assert!(temp_dir.path().join("changed-file_0a.txt").exists());
                        assert!(temp_dir.path().join("changed-file_0b.txt").exists());
                        assert!(temp_dir.path().join("changed-file_0c.txt").exists());

                        assert!(temp_dir.path().join("changed-file_0c.txt").exists());
                        assert!(temp_dir.path().join("changed-file_0c.txt").exists());
                        assert!(temp_dir.path().join("changed-dir_1").join("changed-file_1a.txt").exists());
                        assert!(temp_dir.path()
                                        .join("changed-dir_1")
                                        .join("changed-dir_11")
                                        .join("changed-file_11a.txt")
                                        .exists());
                        assert!(temp_dir.path()
                                        .join("changed-dir_1")
                                        .join("changed-dir_11")
                                        .join("changed-dir_111")
                                        .join("changed-file_111a.txt")
                                        .exists());

                        // run against both
                        let args = Args { regex:       r"(\d+)".to_string(),
                                          replacement: Some("d${1}".to_string()),
                                          recurse:     true,
                                          preview:     false, };
                        app(&args)?;
                        println!("temp: {:?}", temp_dir);

                        assert!(temp_dir.path().join("changed-file_d0a.txt").exists());
                        assert!(temp_dir.path().join("changed-file_d0b.txt").exists());
                        assert!(temp_dir.path().join("changed-file_d0c.txt").exists());

                        assert!(temp_dir.path().join("changed-file_d0c.txt").exists());
                        assert!(temp_dir.path().join("changed-file_d0c.txt").exists());
                        assert!(temp_dir.path().join("changed-dir_d1").join("changed-file_d1a.txt").exists());
                        assert!(temp_dir.path()
                                        .join("changed-dir_d1")
                                        .join("changed-dir_d11")
                                        .join("changed-file_d11a.txt")
                                        .exists());
                        assert!(temp_dir.path()
                                        .join("changed-dir_d1")
                                        .join("changed-dir_d11")
                                        .join("changed-dir_d111")
                                        .join("changed-file_d111a.txt")
                                        .exists());
                        Ok(())
                })
        }
}
