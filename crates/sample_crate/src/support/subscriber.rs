//! Tracing Subscriber configuration for Day07 of Advent of Code 2024.
//!
//! `generate_tracing_subscriber()` is a convenience function designed to be used with `tracint::subscriber::set_global_default(_)`
//! Unfortunately, the return type created by composing Layers is fragile.
//! And the desired trait (Subscriber) is not Sized and therefore not amenable to use of the `--> dyn _` syntax.
//! Similarly, this makes dynamic choice difficult.
//!
//! A prefer solution may be to simple set the global default subscriber *in* the convenience function as a side-effect.
//! This would allow various branches and customizations.
//!
//! For now, this is workable.
//!
//! ## Caution
//! - Tracing is poorly documented and methods poorly named.  One can easily use, e.g., `::fmt()` instead of `::fmt` and be greeted with cryptic or even misdirecting errors.
//!   - I have no solution for this.  *Just be careful!*  It is very easy to lose a lot of time chain one's tail, on seemingly trivial configuration.

use bon::builder;
use tracing::level_filters::LevelFilter;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_error::ErrorLayer;
use tracing_subscriber::prelude::*;

use crate::Result;

#[cfg(debug_assertions)]
const DEFAULT_LOGGING_LEVEL: LevelFilter = LevelFilter::INFO;
#[cfg(debug_assertions)]
const DEFAULT_ERROR_LOGGING_LEVEL: LevelFilter = LevelFilter::TRACE;
#[cfg(not(debug_assertions))]
const DEFAULT_LOGGING_LEVEL: LevelFilter = LevelFilter::WARN;
#[cfg(not(debug_assertions))]
const DEFAULT_ERROR_LOGGING_LEVEL: LevelFilter = LevelFilter::WARN;

/// (Convenience function.) Generates a tracing_subcsriber and sets it as global default, while returning a writer guard.
///
/// # Caveat
///   - Side effect. (sets global default tracing subscriber)
///
/// # Use:
/// ```text
/// fn main() -> Result<()> {
///     let _tracing_writer_worker_guard = generate_tracing_subscriber()?;
///    // ...
///    Ok(())
/// }
/// ```
#[builder]
pub fn activate_global_default_tracing_subscriber(
        env_default_level: Option<LevelFilter>,
        trace_error_level: Option<LevelFilter>,
) -> Result<WorkerGuard> {
        let env_default_level = env_default_level.unwrap_or(DEFAULT_LOGGING_LEVEL);
        let trace_error_level = trace_error_level.unwrap_or(DEFAULT_ERROR_LOGGING_LEVEL);
        let log_writer = std::io::stderr(); // can't set as constant or static

        let envfilter_layer = tracing_subscriber::EnvFilter::builder()
                .with_default_directive(env_default_level.into())
                .from_env_lossy();

        let error_layer = ErrorLayer::default().with_filter(trace_error_level);

        let (non_blocking_writer, trace_writer_guard) = tracing_appender::non_blocking(log_writer);
        let fmt_layer = tracing_subscriber::fmt::Layer::default()
                // .compact()
                // .pretty()
                // .with_timer(<timer>)
                .with_target(true)
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_file(true)
                .with_line_number(true)
                // .with_span_events(FmtSpan::FULL)
                .with_writer(non_blocking_writer);

        let subscriber = tracing_subscriber::Registry::default()
                .with(error_layer)
                .with(fmt_layer.with_filter(envfilter_layer));

        tracing::subscriber::set_global_default(subscriber)?;
        Ok(trace_writer_guard)
}
