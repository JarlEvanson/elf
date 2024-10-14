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

use core::{error, fmt};

use class::{ClassParse, UnsupportedClassError};
use encoding::{EncodingParse, UnsupportedEncodingError};
use header::{ElfHeader, ParseElfHeaderError};
use ident::ElfIdent;

pub mod class;
pub mod encoding;
pub mod header;
pub mod ident;
pub mod program_header;

/// An ELF file.
pub struct ElfFile<'slice, C, E> {
    /// The underlying bytes of the [`ElfFile`].
    bytes: &'slice [u8],
    /// The [`ClassParse`] of this [`ElfFile`].
    class: C,
    /// The [`EncodingParse`] of this [`ElfFile`].
    encoding: E,
}

impl<'slice, C: ClassParse, E: EncodingParse> ElfFile<'slice, C, E> {
    /// Parses an [`ElfFile`] from the provided `slice`.
    ///
    /// # Errors
    ///
    /// For [`ParseElfFileError::InvalidMagicBytes`],
    /// [`ParseElfFileError::UnsupportedElfHeaderVersion`], [`ParseElfFileError::NonZeroPadding`],
    /// [`ParseElfFileError::UnsupportedElfFileVersion`],
    /// [`ParseElfFileError::InvalidElfHeaderSize`],
    /// [`ParseElfFileError::InvalidProgramHeaderSize`],
    /// [`ParseElfFileError::InvalidSectionHeaderSize`], and
    /// [`ParseElfFileError::TooSmallForHeader`], please view the documentation on
    /// [`ParseElfFileError`].
    ///
    /// - Returns [`ParseElfFileError::UnsupportedClass`] if the [`Class`][c] of the [`ElfFile`] is
    ///     unsupported.
    /// - Returns [`ParseElfFileError::UnsupportedEncoding`] if the [`Encoding`][e] of the
    ///     [`ElfFile`] is unsupported.
    ///
    /// [c]: crate::ident::Class
    /// [e]: crate::ident::Encoding
    #[expect(clippy::missing_panics_doc)]
    pub fn parse(slice: &'slice [u8]) -> Result<Self, ParseElfFileError> {
        let elf_header = ElfHeader::<C, E>::parse(slice)?;

        let elf_ident = elf_header.identifier();

        if elf_ident.magic() != ElfIdent::MAGIC_BYTES {
            return Err(ParseElfFileError::InvalidMagicBytes);
        }
        if elf_ident.header_version() != ElfIdent::CURRENT_HEADER_VERSION {
            return Err(ParseElfFileError::UnsupportedElfHeaderVersion);
        }
        if !elf_ident.padding().iter().all(|&val| val == 0) {
            return Err(ParseElfFileError::NonZeroPadding);
        }

        if elf_header.file_version() != ElfHeader::<C, E>::CURRENT_FILE_VERSION {
            return Err(ParseElfFileError::UnsupportedElfFileVersion);
        }
        if elf_header.header_size()
            < elf_header
                .class
                .expected_elf_header_size()
                .try_into()
                .unwrap()
        {
            return Err(ParseElfFileError::InvalidElfHeaderSize);
        }
        if elf_header.program_header_size()
            < elf_header
                .class
                .expected_program_header_size()
                .try_into()
                .unwrap()
        {
            return Err(ParseElfFileError::InvalidProgramHeaderSize);
        }

        let file = Self {
            bytes: slice,
            class: elf_header.class,
            encoding: elf_header.encoding,
        };

        Ok(file)
    }

    /// Returns the [`ElfHeader`] of this [`ElfFile`].
    pub fn header(&self) -> ElfHeader<'slice, C, E> {
        ElfHeader {
            bytes: self.bytes,
            class: self.class,
            encoding: self.encoding,
        }
    }
}

/// Various errors that can occur while parsing an [`ElfFile`].
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum ParseElfFileError {
    /// The [`Class`][c] of the [`ElfFile`] is unsupported.
    ///
    /// [c]: crate::ident::Class
    UnsupportedClass(UnsupportedClassError),
    /// The [`Encoding`][e] of the [`ElfFile`] is unsupported.
    ///
    /// [e]: crate::ident::Encoding
    UnsupportedEncoding(UnsupportedEncodingError),

    /// The bytes occupying the magic number location did not match the ELF magic bytes.
    InvalidMagicBytes,
    /// The [`ElfHeader`] version is unsupported.
    UnsupportedElfHeaderVersion,
    /// The padding of the [`ElfIdent`] was non-zero.
    NonZeroPadding,

    /// The [`ElfFile`] version is unsupported.
    UnsupportedElfFileVersion,
    /// The given size of the [`ElfHeader`] is smaller than expected.
    InvalidElfHeaderSize,
    /// The given size of the [`ProgramHeader`] is smaller than expected.
    InvalidProgramHeaderSize,
    /// The given size of the [`SectionHeader`] is smaller than expected.
    InvalidSectionHeaderSize,
    /// The given `slice` is too small to contain an [`ElfHeader`].
    TooSmallForHeader,
}

impl From<ParseElfHeaderError> for ParseElfFileError {
    fn from(value: ParseElfHeaderError) -> Self {
        match value {
            ParseElfHeaderError::UnsupportedClass(error) => Self::UnsupportedClass(error),
            ParseElfHeaderError::UnsupportedEncoding(error) => Self::UnsupportedEncoding(error),
            ParseElfHeaderError::SliceTooSmall => Self::TooSmallForHeader,
        }
    }
}

impl fmt::Display for ParseElfFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedClass(error) => write!(f, "error parsing ELF file: {error}",),
            Self::UnsupportedEncoding(error) => write!(f, "error parsing ELF file: {error}",),

            Self::InvalidMagicBytes => {
                write!(f, "error parsing ELF identifier: invalid magic bytes")
            }
            Self::UnsupportedElfHeaderVersion => write!(
                f,
                "error parsing ELF identifier: ELF header version not supported",
            ),
            Self::NonZeroPadding => write!(
                f,
                "error parsing ELF identifier: ELF identifier padding was non-zero",
            ),
            Self::UnsupportedElfFileVersion => write!(
                f,
                "error parsing ELF header: ELF file version not supported",
            ),
            Self::InvalidElfHeaderSize => {
                write!(f, "error parsing ELF header: invalid ELF header size",)
            }
            Self::InvalidProgramHeaderSize => {
                write!(f, "error parsing ELF header: invalid program header size",)
            }
            Self::InvalidSectionHeaderSize => {
                write!(f, "error parsing ELF header: invalid section header size",)
            }
            Self::TooSmallForHeader => {
                write!(f, "error parsing ELF header: the given slice is too small")
            }
        }
    }
}

impl error::Error for ParseElfFileError {}
