//! Implementation of 32-bit ELF file parsing.

use core::mem;

use crate::{
    class::{ClassParse, ClassParseBase, UnsupportedClassError},
    header::{ClassParseElfHeader, ElfType, Machine},
    ident::{Class, DefElfIdent},
};

/// A zero-sized object offering methods to safely parse 32-bit ELF files.
#[derive(Clone, Copy, Debug, Hash, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Class32;

impl ClassParse for Class32 {}

impl ClassParseElfHeader for Class32 {
    fn elf_type_offset(self) -> usize {
        mem::offset_of!(Elf32Header, elf_type)
    }

    fn machine_offset(self) -> usize {
        mem::offset_of!(Elf32Header, machine)
    }

    fn file_version_offset(self) -> usize {
        mem::offset_of!(Elf32Header, file_version)
    }

    fn entry_offset(self) -> usize {
        mem::offset_of!(Elf32Header, entry)
    }

    fn flags_offset(self) -> usize {
        mem::offset_of!(Elf32Header, flags)
    }

    fn header_size_offset(self) -> usize {
        mem::offset_of!(Elf32Header, header_size)
    }

    fn program_header_offset_offset(self) -> usize {
        mem::offset_of!(Elf32Header, program_header_offset)
    }

    fn program_header_count_offset(self) -> usize {
        mem::offset_of!(Elf32Header, program_header_count)
    }

    fn program_header_size_offset(self) -> usize {
        mem::offset_of!(Elf32Header, program_header_size)
    }

    fn section_header_offset_offset(self) -> usize {
        mem::offset_of!(Elf32Header, section_header_offset)
    }

    fn section_header_count_offset(self) -> usize {
        mem::offset_of!(Elf32Header, section_header_count)
    }

    fn section_header_size_offset(self) -> usize {
        mem::offset_of!(Elf32Header, section_header_size)
    }

    fn section_header_string_table_index_offset(self) -> usize {
        mem::offset_of!(Elf32Header, section_header_string_table_index)
    }

    fn expected_elf_header_size(self) -> usize {
        mem::size_of::<Elf32Header>()
    }
}

#[repr(C)]
#[expect(clippy::missing_docs_in_private_items)]
pub(crate) struct Elf32Header {
    pub identifier: DefElfIdent,

    pub elf_type: ElfType,
    pub machine: Machine,
    pub file_version: u32,
    pub entry: u32,

    pub program_header_offset: u32,
    pub section_header_offset: u32,

    pub flags: u32,
    pub header_size: u16,

    pub program_header_size: u16,
    pub program_header_count: u16,

    pub section_header_size: u16,
    pub section_header_count: u16,

    pub section_header_string_table_index: u16,
}

impl ClassParseBase for Class32 {
    type ClassUsize = u32;
    type ClassIsize = i32;

    fn from_elf_class(class: Class) -> Result<Self, UnsupportedClassError> {
        if class != Class::CLASS32 {
            return Err(UnsupportedClassError(class));
        }

        Ok(Self)
    }

    fn parse_class_usize_at<E: crate::encoding::EncodingParse>(
        self,
        encoding: E,
        offset: usize,
        data: &[u8],
    ) -> Self::ClassUsize {
        encoding.parse_u32_at(offset, data)
    }

    fn parse_class_isize_at<E: crate::encoding::EncodingParse>(
        self,
        encoding: E,
        offset: usize,
        data: &[u8],
    ) -> Self::ClassIsize {
        encoding.parse_i32_at(offset, data)
    }
}
