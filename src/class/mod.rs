//! Implementation of class aware parsing.

use core::{error, fmt};

use crate::{encoding::EncodingParse, ident::Class};

/// The base definitions of a class aware parser.
pub trait ClassParseBase: Clone + Copy {
    /// An unsigned class sized integer.
    type ClassUsize: TryInto<usize>;
    /// A signed class sized integer.
    type ClassIsize;

    /// Returns the [`ClassParseBase`] instance that corresponds with the given [`Class`].
    ///
    /// # Errors
    ///
    /// Returns [`UnsupportedClassError`] if the given [`Class`] is not supported by this
    /// [`ClassParseBase`] implementation.
    fn from_elf_class(class: Class) -> Result<Self, UnsupportedClassError>;

    /// Returns the unsigned class sized integer at `offset` bytes from the start of the slice.
    ///
    /// # Panics
    ///
    /// Panics if an arithmetic or bounds overflow error occurs.
    fn parse_class_usize_at<E: EncodingParse>(
        self,
        encoding: E,
        offset: usize,
        data: &[u8],
    ) -> Self::ClassUsize;

    /// Returns the signed class sized integer at `offset` bytes from the start of the slice.
    ///
    /// # Panics
    ///
    /// Panics if an arithmetic or bounds overflow error occurs.
    fn parse_class_isize_at<E: EncodingParse>(
        self,
        encoding: E,
        offset: usize,
        data: &[u8],
    ) -> Self::ClassIsize;
}

/// An error that occurs when the code does not support a particular [`Class`]
/// object.
#[derive(Clone, Copy, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnsupportedClassError(Class);

impl fmt::Display for UnsupportedClassError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Class::NONE => write!(f, "no class ELF parsing not supported"),
            Class::CLASS32 => write!(f, "32-bit ELF file parsing not supported"),
            Class::CLASS64 => write!(f, "64-bit ELF file parsing not supported"),
            Class(class) => write!(f, "unknown class({class}) not supported"),
        }
    }
}

impl error::Error for UnsupportedClassError {}
