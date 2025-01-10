//! Support code

pub mod error;
mod subscriber;

pub use error::ErrWrapper;
pub use subscriber::activate_global_default_tracing_subscriber;

pub type Result<T> = std::result::Result<T, ErrWrapper>;
pub type Error = ErrWrapper;
