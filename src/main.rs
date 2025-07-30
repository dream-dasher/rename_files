//! CLI interface to allow regex based file renaming
//!
//! # Example:
//! ```bash
//! clear; el; carr -- '(C|c)argo.*(\..*)' --rep '$1ogra$2' --preview
//! clear; el; carr -- '(C|c)argo.*(\..*)' --rep '${1}ogra$2' --preview
//! ```

use clap::Parser;
use rename_files::{Args, app, error::Result, logging};

fn main() -> Result<()> {
       logging::tracing_subscribe_boilerplate("warn");
       let args = Args::parse();

       match app(&args) {
              Ok(()) => Ok(()), // ensures that change to app success value isn't erased by call code
              Err(e) => {
                     eprintln!("Error: {}", e); // bubling error will not pretty-print cause
                     std::process::exit(1);
              }
       }
}
