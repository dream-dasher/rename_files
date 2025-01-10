//! Interface to allow getting information about Types
use std::fmt;

use clap::ValueEnum;
use owo_colors::OwoColorize;

/// Manual Enumeration of some (std, numeric) rust types.
/// Mostly here to act as a handle/interface to extract other type information
///
/// ## Limitations
/// functions exist as:
///  `<T> ~~~> <W>`
/// For some Ts & Ws.
/// This means that
///
/// `<TypesManual> ~~ X ~~> <(u128 | u64 | i8 | ...)>`
/// is *NOT* a thing.  (Though we could technically make enum-like functionality that does this,
/// via generics with the aid of macros.)
///
/// This ia an *interesting* limitation.  As we may have a code section that ends in a String no matter what.
/// e.g. it just prints stuff.  But there are '*joints*' at which the program needs to have clear
/// type information.
///
/// Therefore
/// I can run a function that returns a string and is run for a different type for each.
/// e.g. `get_min::<u8>() -> String`
/// but **NOT** `get_min::<u8>() -> u8`
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum TypesManual {
        // unsigned - integer
        U8,
        U16,
        U32,
        U64,
        U128,
        USize,
        // signed - integer
        I8,
        I16,
        I32,
        I64,
        I128,
        ISize,
        // signed - float
        F32,
        F64,
}
impl TypesManual {
        /// Get info about type indicatd by type handle (`TypesManual` variant)
        pub fn get_details_as_strings(&self) -> TypeDetails<String> {
                match self {
                        TypesManual::U8 => get_type_details::<u8>().as_strings(),
                        TypesManual::U16 => get_type_details::<u16>().as_strings(),
                        TypesManual::U32 => get_type_details::<u32>().as_strings(),
                        TypesManual::U64 => get_type_details::<u64>().as_strings(),
                        TypesManual::U128 => get_type_details::<u128>().as_strings(),
                        TypesManual::USize => get_type_details::<usize>().as_strings(),
                        TypesManual::I8 => get_type_details::<i8>().as_strings(),
                        TypesManual::I16 => get_type_details::<i16>().as_strings(),
                        TypesManual::I32 => get_type_details::<i32>().as_strings(),
                        TypesManual::I64 => get_type_details::<i64>().as_strings(),
                        TypesManual::I128 => get_type_details::<i128>().as_strings(),
                        TypesManual::ISize => get_type_details::<isize>().as_strings(),
                        TypesManual::F32 => get_type_details::<f32>().as_strings(),
                        TypesManual::F64 => get_type_details::<f64>().as_strings(),
                }
        }
}

/// Trait for extracting useful info about various (std, numeric) rust types.
pub trait TypeInfo {
        fn min_value() -> Self;
        fn max_value() -> Self;
        fn type_name() -> &'static str;
}

/// Convenience macro to implement `TypeInfo` for various types with informally common methods.
macro_rules! impl_type_info {
        ($($t:ty),*) => {
                $(
                    impl TypeInfo for $t {
                        fn min_value() -> Self {
                            <$t>::MIN
                        }
                        fn max_value() -> Self {
                            <$t>::MAX
                        }
                        fn type_name() -> &'static str {
                            std::any::type_name::<$t>()
                        }
                    }
                )*
            };
}
// NOTE: cannot do (i|u)size statically.
impl_type_info!(u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize, f32, f64);

/// Convenience wrapper for usefil information about types.
#[derive(Debug, Clone)]
pub struct TypeDetails<T>
where
        T: std::fmt::Display,
{
        pub name: &'static str,
        pub min:  T,
        pub max:  T,
}
impl<T> TypeDetails<T>
where
        T: std::fmt::Display,
{
        /// Convert the `TypeDetails` to a `TypeDetails` with `String` fields.
        /// This allows all `TypeDetails<T>` to ~~> `TypeDetails<String>`
        pub fn as_strings(&self) -> TypeDetails<String> {
                TypeDetails { name: self.name, min: self.min.to_string(), max: self.max.to_string() }
        }
}

impl<T> fmt::Display for TypeDetails<T>
where
        T: fmt::Display,
{
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                        f,
                        "{}: {}\n {}: {},\n {}: {}",
                        "type".yellow().italic(),
                        self.name.bold().cyan(),
                        "min".yellow().italic(),
                        self.min.to_string().green(),
                        "max".yellow().italic(),
                        self.max.to_string().green()
                )
        }
}

/// Get some useful information about types implementing `TypeInfo`.
pub fn get_type_details<T>() -> TypeDetails<T>
where
        T: TypeInfo + std::fmt::Display,
{
        TypeDetails { name: T::type_name(), min: T::min_value(), max: T::max_value() }
}
