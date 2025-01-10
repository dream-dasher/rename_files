//! # local cargo-xtask
//!
//! ## Note
//! This is an exploratory/scratch use of the xtask pattern.
//! Thus far `just` (see: **justfile**) continues to be the single source for
//! repo-specific scripting needs.
//!
//! As many scripting needs have non-robust dependence on external programs invoked via shell
//! they feel more 'appropriate' listed in the make-like justfile.
//! (Also, just works nicely across language repos.)
//!
//! However, it is often the case that I consider manually implementing functionality
//! that uses tools like fd & sd.  And the quick and successful work creating similar utilities
//! with similar performance and (needs-specific) utility suggests that this may be a nice
//! future direction.  (And in said future just may or may not remain as a discoverability or unifying facade.)

mod types_manual;

use std::{error::Error, result::Result};

use clap::Parser;
use owo_colors::OwoColorize;

use crate::types_manual::*;

/// xtasks, repo convenience tasks
#[derive(Parser, Debug)]
#[command(version, about, long_about, disable_help_subcommand = true, subcommand_help_heading = "input source")]
enum Args {
        /// add two numbers
        Add {
                /// i32
                a: i32,
                /// i32
                b: i32,
        },

        /// List prime components of a rust std type
        // #[arg[(value_enum = "TypesManual")]]
        TypeInfo {
                /// Numeric type to give information about.
                t: TypesManual,
        },

        /// Calculate prime numbers in a range. (In debug mode slows down by 100 million.)
        Primes {
                /// Calculate all primes till some number
                primes_till: Option<usize>,
                /// Only show primes above this number
                #[arg(short = 'n', long = "min")]
                primes_from: Option<usize>,
                /// Show all primes found
                #[arg(short, long)]
                show:        bool,
        },
}

fn main() -> Result<(), Box<dyn Error>> {
        match Args::parse() {
                Args::Add { a, b } => {
                        let sum = a + b;
                        let sum = sum.green();
                        let a = a.red();
                        let b = b.blue();
                        println!("The (hex) sum of {a:>16x}  and {b:>16x} is {sum:>16x}");
                        println!("The (dec) sum of {a:>16}  and {b:>16} is {sum:>16}");
                        println!("The (oct) sum of {a:>16o}  and {b:>16o} is {sum:>16o}");
                        println!("The (bin) sum of {a:>16b}  and {b:>16b} is {sum:>16b}");
                }
                Args::TypeInfo { t } => {
                        const MAX_PRIME_TILL: usize = 10_000_000;
                        let t_deets = t.get_details_as_strings();
                        println!("{}", t_deets);
                        // What follows is a bit silly (with current primes implementation, but I'll keep around for now.)
                        type TForPrimes = usize;
                        let upper_bound = match t_deets.max.parse::<TForPrimes>() {
                                Ok(n) => {
                                        if n <= MAX_PRIME_TILL {
                                                n
                                        } else {
                                                eprintln!(
                                                        "Primes not listed.  {}'s max value ({}) will take a long time for us to calculate with the current method.",
                                                        t_deets.name.green(),
                                                        t_deets.max.blue(),
                                                );
                                                eprintln!("We're going to skip prime calculation.");
                                                eprintln!(
                                                        "({} is the current max for this interface, as it assumes it will be run in debug mode and should have little delay.   Yes, that is quite low.  We are only using a naive Eratosthenes Sieve algorithm.)",
                                                        MAX_PRIME_TILL.magenta()
                                                );
                                                return Ok(());
                                        }
                                }
                                Err(e) => Err(format!(
                                        "Error parsing {}'s max value ({}) as {}: {}",
                                        t_deets.name,
                                        t_deets.max,
                                        std::any::type_name::<TForPrimes>(),
                                        e
                                ))?,
                        };
                        let lower_bound = None;
                        let found_primes = prime_sieve(lower_bound, upper_bound);
                        println!("Number of primes found <= {}: {}", upper_bound, found_primes.len());
                        println!(
                                "which makes the range ({}..={}) {:.1}% prime.",
                                0, // lower_bound.unwrap_or(0),
                                upper_bound,
                                100. * (found_primes.len() as f32) / (upper_bound as f32 + 2.)
                        );
                }
                Args::Primes { primes_till, primes_from, show } => {
                        const DEFAULT_PRIMES_TILL: usize = 12_345;
                        let primes_from_or_default = primes_from.unwrap_or(0);
                        let primes_till_or_default = match primes_till {
                                None => {
                                        println!(
                                                "Hi from scratch_prime.rs.  No primes_till given, defaulting to : {}",
                                                DEFAULT_PRIMES_TILL.cyan()
                                        );
                                        DEFAULT_PRIMES_TILL
                                }
                                Some(p) => {
                                        println!(
                                                "Hi from scratch_prime.rs.  You requested primes for said: {}",
                                                p.blue()
                                        );
                                        p
                                }
                        };
                        println!(
                                "Calculating primes from ({}..={})...",
                                primes_from_or_default.blue(),
                                primes_till_or_default.blue()
                        );
                        if primes_from_or_default > primes_till_or_default {
                                Err("Error: your minimum is larger than your maximum.  Cancelling search.")?
                        };

                        let found_primes = prime_sieve(primes_from, primes_till_or_default);
                        println!(
                                "Number of primes found <= {}: {}",
                                primes_till_or_default.blue(),
                                found_primes.len().green().bold()
                        );
                        println!(
                                "which makes the range ({}..={}) {:.1}% prime.",
                                primes_from_or_default.blue(),
                                primes_till_or_default.blue(),
                                (100. * (found_primes.len() as f32) / (primes_till_or_default as f32 + 2.))
                                        .cyan()
                                        .bold()
                        );
                        if show {
                                println!("{:?}", found_primes.magenta());
                        }
                }
        }
        Ok(())
}

/// I'll be surprised if this works efficiently as a mechanical, literal, procedure.
fn prime_sieve(min: Option<usize>, max: usize) -> Vec<usize> {
        // buncha default yes's
        let mut primes = vec![true; max + 1];
        primes[0] = false;
        primes[1] = false;
        // no need to go past sqrt(n).floor()
        for i in 2..=max.isqrt() {
                // skip if index was marked as multiple of preceding num
                if primes[i] {
                        // first value that's not been sieved would require p >= us, which would be us
                        let mut index = i.pow(2);
                        // false for al p * n indices
                        while index <= max {
                                primes[index] = false;
                                index += i;
                        }
                }
        }
        let min = min.unwrap_or(0);
        // collect unsieved bits
        let mut result = vec![];
        for (i, b) in primes.iter().enumerate().skip(min) {
                if *b {
                        result.push(i);
                }
        }
        result
}
