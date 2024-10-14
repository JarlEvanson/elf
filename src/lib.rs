//! The `elf` crate provides an interface for reading ELF files.
//!
//! # Capabilities
//!
//! ## Works in `no_std` environments
//!
//! This crate provides an ELF file parsing interface which does not allocate or use any `std`
//! features, so it can be used in `no_std` contexts such as bootloaders, kernels, or hypervisors.
//!
//! ## Endian Awareness
//!
//! This crate handles differences between host and file endianness when parsing the ELF file
//! structures and provides generic implementations intended to support various use cases.
//!
//! ## Class Awareness
//!
//! This crate handles differences between host and file class sizes when parsing the ELF file
//! structures and provides generic implementations intended to support various use cases.
//!
//! ## Zero-Alloc Parsing
//!
//! This crate implements parsing in such a manner that avoids heap allocations. ELF structures are
//! lazily parsed with iterators or tables that only parse the requested structure when required.
//!
//! ## Uses no unsafe code
//!
//! This crate contains zero unsafe blocks of code.

#![no_std]

pub mod class;
pub mod encoding;
pub mod ident;

/// Generally, all structs parsed at this level only check for correct length.
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Raw;
/// Generally, all structs parsed at this level only check the correctness of themselves.
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct MinimalParse;

/// Trait representing the various different levels of parsing.
///
/// This trait is sealed.
pub trait ParseState: Clone + Copy + private::ParseStateSealed {}

impl ParseState for Raw {}
impl ParseState for MinimalParse {}

/// Trait representing that the struct has been at least minimally parsed.
pub trait MinimallyParsed: ParseState {}

impl MinimallyParsed for MinimalParse {}

mod private {
    //! Module used to seal [`ParseState`][crate::ParseState].

    /// Sealing trait for [`ParseState`][crate::ParseState].
    pub trait ParseStateSealed {}

    impl ParseStateSealed for crate::Raw {}
    impl ParseStateSealed for crate::MinimalParse {}
}
