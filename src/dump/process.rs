use crate::error::DumpError;
use pelite::image::IMAGE_DIRECTORY_ENTRY_BASERELOC;
use winapi::um::winnt::IMAGE_DATA_DIRECTORY;
use winapi::um::winnt::IMAGE_DOS_HEADER;
use winapi::um::winnt::IMAGE_NT_HEADERS64;
use winapi::um::winnt::IMAGE_SECTION_HEADER;

/// Returns a byte buffer with the entire image.
#[allow(dead_code)]
fn get_image<R>(
    base: usize,
    read: R,
) -> Result<(Vec<u8>, *mut IMAGE_DOS_HEADER, *mut IMAGE_NT_HEADERS64), DumpError>
where
    R: Fn(usize, usize) -> Option<Vec<u8>>,
{
    // DOS_HEADER
    //
    let mut dos_header =
        read(base, std::mem::size_of::<IMAGE_DOS_HEADER>()).ok_or(DumpError::ReadMemory)?;
    let dos_header = super::get_dos_header(&mut dos_header)?;

    // NT_HEADER
    //
    let mut nt_header = read(
        base + unsafe { (*dos_header).e_lfanew } as usize,
        std::mem::size_of::<IMAGE_NT_HEADERS64>(),
    )
    .ok_or(DumpError::ReadMemory)?;
    let nt_header = super::get_nt_header(&mut nt_header)?;

    // Read the image to memory
    //
    let memory = read(base, unsafe { (*nt_header).OptionalHeader.SizeOfImage }
        as usize)
    .ok_or(DumpError::ReadMemory)?;

    Ok((memory, dos_header, nt_header))
}

/// Dumps the specified image.
///
/// # Arguments
/// - `base`: The base address of the image.
/// - `read`: A closure that reads memory at the address and returns it.
///
/// # Return
/// Returns the raw bytes of the image.
#[allow(dead_code)]
pub(crate) fn dump<R>(base: usize, read: R) -> Result<Vec<u8>, DumpError>
where
    R: Fn(usize, usize) -> Option<Vec<u8>>,
{
    let (mut buffer, dos_header, nt_header) = get_image(base, read)?;

    // Extract the section header
    //
    let optional_header_offset = memoffset::offset_of!(IMAGE_NT_HEADERS64, OptionalHeader);
    let section_header: *mut IMAGE_SECTION_HEADER = unsafe {
        buffer
            .as_mut_ptr()
            .offset((*dos_header).e_lfanew as isize)
            .offset(optional_header_offset as isize)
            .offset((*nt_header).FileHeader.SizeOfOptionalHeader as isize) as _
    };

    // Fix the section headers
    //
    for i in 0..unsafe { (*nt_header).FileHeader.NumberOfSections } {
        let section: *mut IMAGE_SECTION_HEADER = unsafe { section_header.offset(i as isize) };

        let section_address = unsafe { (*section).VirtualAddress };
        let section_size = *unsafe { (*section).Misc.VirtualSize() };

        // Rewrite the file offsets to the virtual addresses
        //
        unsafe {
            (*section).PointerToRawData = section_address;
            (*section).SizeOfRawData = section_size;
        }

        // Rewrite the base relocation to the ".reloc" section
        //
        let name = unsafe { (*section).Name.as_ref() };
        if name == b".reloc\x00\x00" {
            unsafe {
                (*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] =
                    IMAGE_DATA_DIRECTORY {
                        VirtualAddress: section_address,
                        Size: section_size,
                    }
            }
        }
    }

    Ok(buffer)
}
