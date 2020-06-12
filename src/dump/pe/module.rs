use crate::dump::pe::section::Section;
use crate::dump::{get_dos_header, get_nt_header};
use crate::error::DumpError;
use pelite::pe64::image::{IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, IMAGE_NUMBEROF_DIRECTORY_ENTRIES};
use winapi::um::winnt::IMAGE_DOS_HEADER;
use winapi::um::winnt::IMAGE_FILE_HEADER;
use winapi::um::winnt::IMAGE_NT_HEADERS64;
use winapi::um::winnt::IMAGE_OPTIONAL_HEADER32;
use winapi::um::winnt::IMAGE_SECTION_HEADER;

const IMAGE_DOS_HEADER_SIZE: usize = std::mem::size_of::<IMAGE_DOS_HEADER>();
const IMAGE_NT_HEADER_SIZE: usize = std::mem::size_of::<IMAGE_NT_HEADERS64>();
const IMAGE_OPTIONAL_HEADER_SIZE: usize = std::mem::size_of::<IMAGE_OPTIONAL_HEADER32>();
const IMAGE_SECTION_HEADER_SIZE: usize = std::mem::size_of::<IMAGE_SECTION_HEADER>();
const IMAGE_FILE_HEADER_SIZE: usize = std::mem::size_of::<IMAGE_FILE_HEADER>();

macro_rules! align {
    ($value: expr, $alignment: expr) => {
        (($value + $alignment - 1) / $alignment) * $alignment
    };
}

/// Represents a 64 bit portable executable module.
pub struct Module {
    /// The base address of the module.
    base_address: usize,

    /// The memory of the dos header.
    dos_header_memory: Vec<u8>,

    /// The dos header of the module.
    dos_header: Option<IMAGE_DOS_HEADER>,

    /// The dos stub.
    dos_stub: Vec<u8>,

    /// The memory of the nt header.
    nt_header_memory: Vec<u8>,

    /// The nt header of the module.
    nt_header: Option<IMAGE_NT_HEADERS64>,

    /// The sections of the module.
    sections: Vec<Section>,
}

impl Module {
    /// Creates a new module object. However, this does not dump the image.
    pub const fn new(base_address: usize) -> Self {
        Self {
            base_address,
            dos_header_memory: Vec::new(),
            dos_header: None,
            dos_stub: Vec::new(),
            nt_header_memory: Vec::new(),
            nt_header: None,
            sections: Vec::new(),
        }
    }

    /// Dumps the module from memory.
    pub fn dump<R: Fn(usize, usize) -> Option<Vec<u8>>>(
        &mut self,
        read: R,
    ) -> Result<(), DumpError> {
        self.dump_headers(&read)?;
        self.dump_sections(&read)?;

        Ok(())
    }

    /// Dumps the dos, nt and section headers of the module.
    /// This does also dump the dos stub, since it's in between the dos and nt headers.
    fn dump_headers<R: Fn(usize, usize) -> Option<Vec<u8>>>(
        &mut self,
        read: R,
    ) -> Result<(), DumpError> {
        println!("Dumping the headers.");

        // IMAGE_DOS_HEADER
        //
        let mut dos_header_memory =
            read(self.base_address, IMAGE_DOS_HEADER_SIZE).ok_or(DumpError::ReadMemory)?;
        let dos_header = get_dos_header(&mut dos_header_memory)?;

        self.dos_header_memory = dos_header_memory;
        self.dos_header = Some(unsafe { dos_header.read() });

        // Dos Stub
        //
        let e_lfanew = unsafe { (*dos_header).e_lfanew } as usize;

        let dos_stub_ptr = self.base_address + IMAGE_DOS_HEADER_SIZE;
        let dos_stub_size = e_lfanew - IMAGE_DOS_HEADER_SIZE;

        self.dos_stub = read(dos_stub_ptr, dos_stub_size).ok_or(DumpError::ReadMemory)?;

        // IMAGE_NT_HEADER
        //
        let nt_header_ptr = self.base_address + e_lfanew;

        let mut nt_header_memory =
            read(nt_header_ptr, IMAGE_NT_HEADER_SIZE).ok_or(DumpError::ReadMemory)?;
        let nt_header = get_nt_header(&mut nt_header_memory)?;

        self.nt_header_memory = nt_header_memory;
        self.nt_header = Some(unsafe { nt_header.read() });

        // IMAGE_SECTION_HEADER
        //

        // See: https://stackoverflow.com/a/29278238
        let optional_header_offset = memoffset::offset_of!(IMAGE_NT_HEADERS64, OptionalHeader);
        let optional_header_size = unsafe { (*nt_header).FileHeader.SizeOfOptionalHeader } as usize;

        let section_count = unsafe { (*nt_header).FileHeader.NumberOfSections };
        let mut section_ptr = nt_header_ptr + optional_header_offset + optional_header_size;

        println!("Found {:?} sections.", section_count);
        println!("First section header at {:x?}", section_ptr);

        for _ in 0..section_count {
            let mut section_header_memory = read(section_ptr, IMAGE_SECTION_HEADER_SIZE)
                .ok_or_else(|| DumpError::ReadMemory)
                .unwrap_or_else(|_| {
                    println!("Failed to read section header at {:x?}.", section_ptr);
                    vec![0u8; IMAGE_SECTION_HEADER_SIZE]
                });

            let section_header = section_header_memory.as_mut_ptr() as *mut IMAGE_SECTION_HEADER;

            self.sections.push(Section {
                header_memory: section_header_memory,
                header: unsafe { section_header.read() },
                content: Vec::new(),
            });

            section_ptr += IMAGE_SECTION_HEADER_SIZE;
        }

        Ok(())
    }

    /// Dumps the sections from the memory.
    fn dump_sections<R: Fn(usize, usize) -> Option<Vec<u8>>>(
        &mut self,
        read: R,
    ) -> Result<(), DumpError> {
        println!("Dumping the sections.");

        // Get the section content
        //
        for section in self.sections.iter_mut() {
            let section: &mut Section = section;

            // Read the section content
            //
            let address = self.base_address + section.header.VirtualAddress as usize;
            let size = *unsafe { section.header.Misc.VirtualSize() } as usize;

            // Find the size
            let size = if size < 100 {
                size
            } else {
                Self::calculate_section_size(&read, address, size)
            };

            // Read the content
            section.content = read(address, size).unwrap_or_default()
        }

        Ok(())
    }

    /// Calculates the section size in case the section is bigger in memory than on disk.
    fn calculate_section_size<R: Fn(usize, usize) -> Option<Vec<u8>>>(
        read: R,
        address: usize,
        size: usize,
    ) -> usize {
        // const MAX_READ_SIZE: usize = 100;
        //
        // let mut current_read_size = size % MAX_READ_SIZE;
        // let mut current_offset = address + size - current_read_size;
        //
        // while current_offset > address {
        //     let bytes = read(current_offset, current_read_size).unwrap_or_default();
        //     let instructions = bytes.iter().filter(|&&b| b != 0).count();
        //
        //     current_read_size += MAX_READ_SIZE;
        //     current_offset += current_read_size;
        // }

        size
    }

    /// Aligns the section header and updates the size of the data.
    pub fn align_sections(&mut self) -> Option<()> {
        println!("Aligning the sections.");

        let section_alignment = self.nt_header.map(|h| h.OptionalHeader.FileAlignment)?;
        let file_alignment = self.nt_header.map(|h| h.OptionalHeader.SectionAlignment)?;

        let mut file_size = self.dos_header?.e_lfanew as usize
            + 0x4
            + IMAGE_FILE_HEADER_SIZE
            + self.nt_header?.FileHeader.SizeOfOptionalHeader as usize
            + (self.nt_header?.FileHeader.NumberOfSections as usize * IMAGE_SECTION_HEADER_SIZE);

        for section in self.sections.iter_mut() {
            let section: &mut Section = section;

            // VirtualAddress and VirtualSize
            //
            section.header.VirtualAddress =
                align!(section.header.VirtualAddress, section_alignment);

            let virtual_size = unsafe { section.header.Misc.VirtualSize_mut() };
            *virtual_size = align!(*virtual_size, section_alignment);

            // PointerToRawData and SizeOfRawData
            //
            section.header.PointerToRawData = align!(file_size, file_alignment as usize) as u32;
            section.header.SizeOfRawData =
                align!(section.content.len(), file_alignment as usize) as u32;

            // Update the file size
            //
            file_size = (section.header.PointerToRawData + section.header.SizeOfRawData) as _;
        }

        Some(())
    }

    /// Fixes the pe header.
    pub fn fix_header(&mut self) -> Option<()> {
        let header = self.nt_header_memory.as_mut_ptr() as *mut IMAGE_NT_HEADERS64;

        // Remove import directories
        //
        unsafe {
            (*header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT]
                .VirtualAddress = 0;
            (*header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;

            for i in 0..(*header).OptionalHeader.NumberOfRvaAndSizes {
                if i >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES as _ {
                    break;
                }

                (*header).OptionalHeader.DataDirectory[i as usize].Size = 0;
                (*header).OptionalHeader.DataDirectory[i as usize].VirtualAddress = 0;
            }
        }

        // Update the headers and calculate the correct values
        //
        unsafe {
            (*header).OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES as _;
            (*header).OptionalHeader.ImageBase = self.base_address as _;
            (*header).OptionalHeader.SizeOfImage = self.get_image_size();
            (*header).OptionalHeader.SizeOfHeaders = align!(
                self.dos_header?.e_lfanew as usize
                    + 0x4
                    + IMAGE_FILE_HEADER_SIZE as usize
                    + (*header).FileHeader.SizeOfOptionalHeader as usize
                    + (self.sections.len() * IMAGE_SECTION_HEADER_SIZE) as usize,
                (*header).OptionalHeader.FileAlignment as usize
            ) as _;
            (*header).FileHeader.SizeOfOptionalHeader = IMAGE_OPTIONAL_HEADER_SIZE as _;
        }

        Some(())
    }

    /// Finds the image base by iterating trough the sections and finding the last one.
    /// The `address + size` of the last section is the total image size.
    fn get_image_size(&mut self) -> u32 {
        let mut last_section = 0;

        // Iterate through the sections
        //
        for section in self.sections.iter() {
            let section: &Section = section;

            // Calculate the end of the current section
            //
            let section_address =
                section.header.VirtualAddress + unsafe { section.header.Misc.VirtualSize() };

            if section_address > last_section {
                last_section = section_address;
            }
        }

        last_section
    }

    /// Returns the current module as a byte buffer.
    pub fn get_buffer(&mut self) -> Vec<u8> {
        let mut module = Vec::new();

        module.append(&mut self.dos_header_memory);
        module.append(&mut self.dos_stub);
        module.append(&mut self.nt_header_memory);

        for section in self.sections.iter_mut() {
            module.append(&mut section.header_memory);
        }

        for section in self.sections.iter_mut() {
            // TODO:  PointerToRawData > dwFileOffset => Padding needed
            module.append(&mut section.content);
            // TODO:  DataSize < SizeOfRawData => Padding needed
        }

        module
    }
}
