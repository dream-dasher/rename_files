```rust
//! Bits 'n Bobs box.
//! Unused code snippets that may be useful later.

/// Checks for a literal `.` prefix on a entry
///
/// # Unused Because:o
/// Already have general regex search.  May implement if need an ergonomic 'quick path'.
///
/// # Note: This will trigger on the `.` used to indicate the 'local' directory
fn is_hidden(entry: &walkdir::DirEntry) -> bool {
    let is_hidden = entry.file_name().to_str().map(|s| s.starts_with('.')).unwrap_or(false);
    if is_hidden {
        tracing::trace!("Ignoring hidden file: {:?}", entry.path());
    } else {
        tracing::trace!("Not a hidden file: {:?}", entry.path());
    }
    is_hidden
}

/// Just a syntax check and familiarization test for working with tempdir and fs asserts.
#[test]
fn xp_test_fs() -> Result<()> {
    tracing::debug!("creatind tempdir");
    let dir_root = utility_test_dir_gen()?;

    tracing::debug!("debug level statement");
    println!("testing\na\nb\nc\nd\ntesting\n");

    println!("temp: {:?}", dir_root);
    let nf_0d = File::create(dir_root.path().join("new_file_0d.txt"))?;
    println!("temp: {:?}", dir_root);
    println!("new_file_0d: {:?}", nf_0d);

    assert!(!dir_root.path().join("blahblahblah").exists());
    assert!(dir_root.path().join("new_file_0d.txt").exists());
    #[cfg(target_os = "macos")]
    {
        // NOTE: MacOS filesystem by *default* is case-*in*sensitive
        //       This is *not* an invariant on MacOS (despite my cfg logic)
        //       Nor is it the default in Linux, commonly
        assert!(dir_root.path().join("New_file_0d.txt").exists());
        assert!(dir_root.path().join("nEw_FiLe_0D.tXt").exists());
    }

    dir_root.close()?;
    Ok(())
}


/// # "Property Test" using random sampling with QuickCheck
///
/// TODO: these are silly PoC
#[cfg(test)]
mod tests_random_sample_property {
        use super::*;
        use anyhow::{Result, anyhow};
        use quickcheck::{Arbitrary, Gen, TestResult};
        use quickcheck_macros::quickcheck;
        use test_log::test;

        /// Custom generator for known-good regex strings
        #[derive(Debug, Clone)]
        struct SampleValidPreRegex(String);

        impl Arbitrary for SampleValidPreRegex {
                fn arbitrary(g: &mut Gen) -> Self {
                        let patterns = [
                                "file.*",
                                r"\d+",
                                "[a-z]+",
                                ".*\\.txt",
                                "(test|spec)",
                                "[A-Za-z_][A-Za-z0-9_]*",
                        ];
                        let idx = usize::arbitrary(g) % patterns.len();
                        SampleValidPreRegex(patterns[idx].to_string())
                }
        }

        /// Test that preview=true never changes filesystem regardless of other args
        #[quickcheck]
        fn test_qc_no_change_if_preview(
                regex: SampleValidPreRegex,
                paths: Vec<std::path::PathBuf>,
                replacement: Option<String>,
                recurse: bool,
        ) -> Result<()> {
                let temp_dir = utility_fixed_populated_tempdir_gen()?;
                let args = Args {
                        regex: regex.0,
                        replacement,
                        recurse,
                        preview: true, // This should prevent all changes
                };
                utility_with_global_mutex(|| {
                        std::env::set_current_dir(temp_dir.path())?;
                        let mut before_state = utility_collect_directory_state(".")?;
                        // println!("{:?}", path.to_string_lossy().len());
                        println!("\n\n------------------------{:?}", paths.len());

                        // ignore result (e.g. due to bad regex), we only care about filesystem state
                        let _ = app(&args);
                        let mut after_state = utility_collect_directory_state(".")?;

                        before_state.sort();
                        after_state.sort();

                        match before_state == after_state {
                                true => Ok(()),
                                false => Err(anyhow!("Filesystem state changed")),
                        }
                })
        }

        /// Test that replacement=None never changes filesystem
        #[quickcheck]
        fn test_qc_no_change_if_norep(regex: SampleValidPreRegex, recurse: bool) -> TestResult {
                let result = utility_with_global_mutex(|| -> Result<bool> {
                        let temp_dir = utility_fixed_populated_tempdir_gen()?;
                        std::env::set_current_dir(temp_dir.path())?;

                        let mut before_state = utility_collect_directory_state(".")?;

                        let args = Args {
                                regex: regex.0,
                                replacement: None, // This should prevent all changes
                                recurse,
                                preview: false,
                        };

                        let _ = app(&args); // Ignore result, just check filesystem state

                        let mut after_state = utility_collect_directory_state(".")?;

                        before_state.sort();
                        after_state.sort();

                        Ok(before_state == after_state)
                });

                match result {
                        Ok(unchanged) => TestResult::from_bool(unchanged),
                        Err(_) => TestResult::discard(),
                }
        }

        /// Test replacement behavior using built-in PathBuf generator
        #[quickcheck]
        fn test_qc_replacement_uses_real_filenames(
                path: std::path::PathBuf,
                regex: SampleValidPreRegex,
                replacement: String,
        ) -> TestResult {
                use regex::Regex;

                // Extract filename from generated path
                let filename = match path.file_name().and_then(|n| n.to_str()) {
                        Some(f) if !f.is_empty() => f,
                        _ => return TestResult::discard(),
                };

                let re = match Regex::new(&regex.0) {
                        Ok(re) => re,
                        Err(_) => return TestResult::discard(),
                };

                // Test that the same input produces the same output (determinism)
                let result1 = re.replace(filename, &replacement);
                let result2 = re.replace(filename, &replacement);

                TestResult::from_bool(result1 == result2)
        }

        /// Test no changes when regex doesn't match anything
        #[quickcheck]
        fn test_qc_no_change_if_no_matches(replacement: Option<String>, recurse: bool) -> TestResult {
                let result = utility_with_global_mutex(|| -> Result<bool> {
                        let temp_dir = utility_fixed_populated_tempdir_gen()?;
                        std::env::set_current_dir(temp_dir.path())?;

                        let mut before_state = utility_collect_directory_state(".")?;

                        let args = Args {
                                regex: "definitely_wont_match_anything_xyz123".to_string(),
                                replacement,
                                recurse,
                                preview: false,
                        };

                        let _ = app(&args); // Ignore result, just check filesystem state

                        let mut after_state = utility_collect_directory_state(".")?;

                        before_state.sort();
                        after_state.sort();

                        Ok(before_state == after_state)
                });

                match result {
                        Ok(unchanged) => TestResult::from_bool(unchanged),
                        Err(_) => TestResult::discard(),
                }
        }
}
#[cfg(test)]
mod test_test {

        use rand::seq::IndexedRandom;
        /// # broken: attempt to filter pathbugs not solving problems -- various issues like paths too long, encoding, and there's still some issue with what should be guaranteed to have a parent apparently not (despite testing directly prior)
        /// # Generates a populated temporary directory from a vector of paths.
        ///
        /// - Reporudcible: creates a rand seed from hash of vector for reproducibility
        /// - QuickCheck compatible: `vec<Path>` will has a default generator
        ///
        fn utility_rand_from_vec_tempdir_gen(pathbufs: Vec<std::path::PathBuf>) -> Result<TempDir> {
                use rand::rngs::StdRng;
                use rand::{Rng, SeedableRng};
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};

                // let hash = paths.hash();
                // // convert hash to `u64`
                // let hash_u64 = hash as u64;
                // // create **rand** seed with `sead_from_u64`
                // let seed = rand::SeedableRng::seed_from_u64(hash_u64);
                // // choose number from 0..len -> numbers to right of that are files, left are dirs
                // // child_dirs = 0, for each child dir, pop off and choose from 0..child_dirs, appending to said dir (0= parent)
                // //for files, do the same thing, but no longer incrementing the child_dirs number

                let dir_root = TempDir::new()?;
                if pathbufs.is_empty() {
                        return Ok(dir_root);
                }
                // clean empty, absolute, and non-standard ("symbolic") paths
                let pathbufs: Vec<_> = pathbufs
                        .into_iter()
                        .filter_map(|p| {
                                let cannonicalized = p.canonicalize().ok()?;
                                let path_str = cannonicalized.to_string_lossy();

                                // Filter out empty and dir paths
                                if path_str.is_empty() || path_str.ends_with('/') {
                                        None
                                } else {
                                        Some(cannonicalized)
                                }
                        })
                        .collect();
                tracing::error!("Filtered paths: {:?}", pathbufs);

                // hash for reproducibility
                // while we'd get reproducibility from just, for example `paths.len() as u64`
                // that would result in identical rand values for dirs of same number of elements
                // creating less variability than we'd like
                let mut rng_seeded = {
                        let mut hasher = DefaultHasher::new();
                        pathbufs.hash(&mut hasher);
                        let hash = hasher.finish();
                        StdRng::seed_from_u64(hash)
                };

                // Split pathbs vec into dir-pathbs and file-pathbs
                let dirfile_splitpoint = rng_seeded.random_range(0..=pathbufs.len());
                let (dir_pathbufs, file_pathbufs) = pathbufs.split_at(dirfile_splitpoint);
                let mut joined_dirs = vec![dir_root.path().to_path_buf()]; // guaranteed to include root

                // let dir_111 = dir_11.join("dir_111");
                // fs::create_dir(&dir_1)?;
                // fs::create_dir(&dir_11)?;
                // fs::create_dir(&dir_111)?;
                // File::create(dir_1.join("file_1a.txt"))?;

                // child_dirs = 0, for each child dir, pop off and choose from 0..child_dirs, appending to said dir (0= parent)
                // join dirs with random attachment points
                for dir in dir_pathbufs {
                        let entry = joined_dirs
                                .choose(&mut rng_seeded)
                                .expect("joined_dirs guaranteed not empty");
                        let joined_path = entry.join(dir);
                        // perf: `_all` doesn't seem needed for dir creation here, but docs suggest it is -- keeping this despite repeated mkdir calls as of 1.88
                        fs::create_dir_all(&joined_path)?;
                        joined_dirs.push(joined_path);
                }
                for file in file_pathbufs {
                        let entry = joined_dirs
                                .choose(&mut rng_seeded)
                                .expect("joined_dirs guaranteed not empty");
                        let joined_path = entry.join(file);
                        if entry.parent().is_some() {
                                // quandry: `_all` does seem needed for dir creation here...
                                fs::create_dir_all(joined_path.parent().expect("guaranteed to exist"))?;
                        }
                        tracing::info!("Creating file: {}", joined_path.display());
                        File::create(&joined_path)?;
                }
                Ok(dir_root)
        }
        use super::*;
        use anyhow::Result;
        use quickcheck_macros::quickcheck;
        use test_log::test;
        #[test]
        fn test_rand_gen() -> Result<()> {
                let test_paths = vec![
                        std::path::PathBuf::from("test_file1.txt"),
                        std::path::PathBuf::from("subdir/test_file2.txt"),
                        std::path::PathBuf::from("another_dir"),
                        std::path::PathBuf::from("deep/nested/path/file.rs"),
                ];
                let _x = utility_rand_from_vec_tempdir_gen(test_paths)?;

                Ok(())
        }

        #[test]
        #[quickcheck]
        fn test_qc_rand_gen(pathbufs: Vec<std::path::PathBuf>) -> Result<()> {
                let _x = utility_rand_from_vec_tempdir_gen(pathbufs)?;

                Ok(())
        }
}
```
