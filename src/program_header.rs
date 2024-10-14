//! Definitions for the ELF program headers and their associated table.

use core::fmt;

use crate::{
    class::{ClassParse, ClassParseBase},
    encoding::EncodingParse,
};

/// Structure that describes information required to prepare the program for execution.
#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub struct RawProgramHeader<'slice, C, E> {
    /// The underlying bytes of the [`RawProgramHeader`].
    bytes: &'slice [u8],
    /// The [`ClassParseRawProgramHeader`] of this [`ProgramHeader`].
    class: C,
    /// The [`EncodingParse`] of this [`RawProgramHeader`].
    encoding: E,
}

impl<'slice, C: ClassParse, E: EncodingParse> RawProgramHeader<'slice, C, E> {
    /// Parses a [`RawProgramHeader`] from the provided `slice` using the given `class` and `encoding`.
    ///
    /// Returns `None` if the given `slice` is too small to contain an ELF program header.
    pub fn parse(class: C, encoding: E, slice: &'slice [u8]) -> Option<Self> {
        if slice.len() < class.expected_program_header_size() {
            return None;
        }

        let program_header = Self {
            bytes: slice,
            class,
            encoding,
        };

        Some(program_header)
    }

    /// Returns the [`SegmentType`], which determines how to interpret the [`RawProgramHeader`]'s
    /// remaining fields.
    pub fn segment_type(&self) -> SegmentType {
        SegmentType(
            self.encoding
                .parse_u32_at(self.class.segment_type_offset(), self.bytes),
        )
    }

    /// Returns various flags relevant to the segment.
    pub fn flags(&self) -> SegmentFlags {
        SegmentFlags(
            self.encoding
                .parse_u32_at(self.class.segment_flags_offset(), self.bytes),
        )
    }

    /// Returns the offset from the beginning of the file at which the first byte of the segment
    /// exists.
    pub fn file_offset(&self) -> C::ClassUsize {
        self.class.parse_class_usize_at(
            self.encoding,
            self.class.segment_file_offset_offset(),
            self.bytes,
        )
    }

    /// Returns the number of bytes in the file 's view of the segment.
    pub fn file_size(&self) -> C::ClassUsize {
        self.class.parse_class_usize_at(
            self.encoding,
            self.class.segment_file_size_offset(),
            self.bytes,
        )
    }

    /// Returns the virtual address at which the first bytes of the segment reside in memory when
    /// loaded.
    pub fn virtual_address(&self) -> C::ClassUsize {
        self.class.parse_class_usize_at(
            self.encoding,
            self.class.segment_virtual_address_offset(),
            self.bytes,
        )
    }

    /// Returns the physical address at which the first bytes of the segment reside in memory when
    /// loaded.
    pub fn physical_address(&self) -> C::ClassUsize {
        self.class.parse_class_usize_at(
            self.encoding,
            self.class.segment_physical_address_offset(),
            self.bytes,
        )
    }

    /// Returns the number of bytes in the loaded segment.
    pub fn memory_size(&self) -> C::ClassUsize {
        self.class.parse_class_usize_at(
            self.encoding,
            self.class.segment_memory_size_offset(),
            self.bytes,
        )
    }

    /// Returns the alignment of the segment.
    ///
    /// This alignment is applicable both in the file and in memory.
    pub fn alignment(&self) -> C::ClassUsize {
        self.class.parse_class_usize_at(
            self.encoding,
            self.class.segment_alignment_offset(),
            self.bytes,
        )
    }
}

impl<C: ClassParse, E: EncodingParse> fmt::Debug for RawProgramHeader<'_, C, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug_struct = f.debug_struct("RawProgramHeader");

        debug_struct.field("segment_type", &self.segment_type());
        debug_struct.field("flags", &self.flags());
        debug_struct.field("file_offset", &self.file_offset());
        debug_struct.field("virtual_address", &self.virtual_address());
        debug_struct.field("physical_address", &self.physical_address());
        debug_struct.field("file_size", &self.file_size());
        debug_struct.field("memory_size", &self.memory_size());
        debug_struct.field("alignment", &self.alignment());

        debug_struct.finish()
    }
}

/// The type of the segment the associated [`ProgramHeader`] contains.
#[repr(transparent)]
#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct SegmentType(pub u32);

impl SegmentType {
    /// Unsued [`ProgramHeader`].
    pub const NULL: Self = Self(0);
    /// Loadable segment.
    pub const LOAD: Self = Self(1);
    /// Dynamic linking information.
    pub const DYNAMIC: Self = Self(2);
    /// The program interpreter.
    pub const INTERPRETER: Self = Self(3);
    /// Auxiliary information.
    pub const NOTE: Self = Self(4);
    /// Reserved.
    pub const SHLIB: Self = Self(5);
    /// [`ProgramHeader`] table.
    pub const PHDR: Self = Self(6);
    /// Thread local storage.
    pub const TLS: Self = Self(7);
}

impl fmt::Debug for SegmentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NULL => f.pad("Null"),
            Self::LOAD => f.pad("Load"),
            Self::DYNAMIC => f.pad("Dynamic"),
            Self::INTERPRETER => f.pad("Interpreter"),
            Self::NOTE => f.pad("Note"),
            Self::SHLIB => f.pad("Shlib"),
            Self::PHDR => f.pad("ProgramHeaders"),
            Self::TLS => f.pad("Tls"),
            segment_type => f.debug_tuple("SegmentType").field(&segment_type.0).finish(),
        }
    }
}

/// The permissions of a [`SegmentType::LOAD`] segment.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct SegmentFlags(pub u32);

impl SegmentFlags {
    /// The segment should be marked executable.
    pub const EXECUTE: Self = Self(0x1);
    /// The segment should be marked writable.
    pub const WRITE: Self = Self(0x2);
    /// The segment should be marked readable.
    pub const READ: Self = Self(0x4);

    /// Mask of the bits reserved for operating system specific semantics.
    pub const MASK_OS: Self = Self(0x0FF0_FFFF);
    /// Mask of the bits reserved for processor specific semantics.
    pub const MASK_PROCESSOR: Self = Self(0xF000_0000);
}

/// The information required to implement class aware parsing of an ELF program header.
pub trait ClassParseProgramHeader: ClassParseBase {
    /// The offset of the [`SegmentType`].
    fn segment_type_offset(self) -> usize;
    /// The offset of the segment flags.
    fn segment_flags_offset(self) -> usize;

    /// The offset of the file offset of the segment.
    fn segment_file_offset_offset(self) -> usize;
    /// The offset of the number of bytes in the file's view of the segment.
    fn segment_file_size_offset(self) -> usize;

    /// The offset of the virtual address of the loaded segment.
    fn segment_virtual_address_offset(self) -> usize;
    /// The offset of the physical address of the loaded segment.
    fn segment_physical_address_offset(self) -> usize;
    /// The offset of the number of bytes in the loaded segment.
    fn segment_memory_size_offset(self) -> usize;

    /// The offset of the alignment of the segment.
    fn segment_alignment_offset(self) -> usize;

    /// The expected size of an ELF program header.
    fn expected_program_header_size(self) -> usize;
}
