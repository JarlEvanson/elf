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
