//! Error handling for rename_files

use owo_colors::OwoColorize;
use thiserror::Error;

/// Result type alias for rename_files operations
pub type Result<T> = core::result::Result<T, Error>;

/// Simple error enum that wraps common error types
#[derive(Debug, Error)]
pub enum Error {
        /// Regex compilation failed
        #[error("Invalid regex: {0}")]
        Regex(#[from] regex::Error),

        /// File system operation failed
        #[error("File system error: {0}")]
        Io(#[from] std::io::Error),

        /// Directory walking failed
        #[error("Directory walking error: {0}")]
        WalkDir(#[from] walkdir::Error),

        /// User provided ambiguous replacement syntax
        #[error("{}", format_ambiguous_replacement(ambiguous_whole))]
        AmbiguousReplacementSyntax { ambiguous_whole: String, ambiguous_head: String },
}

/// Helper function to create error display for `AmbiguousReplacementSyntax`
fn format_ambiguous_replacement(ambiguous_whole: &str) -> String {
        // separate digits from dollar
        let without_dollar = ambiguous_whole.trim_start_matches('$');
        let digits: String = without_dollar.chars().take_while(|c| c.is_ascii_digit()).collect();
        let text: String = without_dollar.chars().skip_while(|c| c.is_ascii_digit()).collect();

        format!(
                "Ambiguous replacement syntax: '{}' is read as '{}' but you probably meant '{}'. Use '{}' instead (or use {{}} around capture group identifiers).",
                ambiguous_whole.yellow(),
                format!("${{{without_dollar}}}").red(),
                format!("${{{}}}{text}", digits).green(),
                format!("${{{}}}{text}", digits).green()
        )
}
