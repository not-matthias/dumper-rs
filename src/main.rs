use std::ffi::CString;

use crate::error::DumpError;
use core::driver::context::{Context, DriverOperations};
use pelite::image::{
    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS_SIGNATURE,
};
use std::fs::File;
use std::io::Write;
use winapi::_core::mem::MaybeUninit;
use winapi::um::fileapi::GetFileAttributesExA;
use winapi::um::fileapi::WIN32_FILE_ATTRIBUTE_DATA;
use winapi::um::winnt::IMAGE_DATA_DIRECTORY;
use winapi::um::winnt::IMAGE_DOS_HEADER;
use winapi::um::winnt::IMAGE_NT_HEADERS64;
use winapi::um::winnt::IMAGE_SECTION_HEADER;

pub mod driver;
pub mod error;
pub mod process;

/// Finds the file size of the specified file.
///
/// # Example
/// ```no_run
/// const FILE_PATH: &str = "C:\\Windows\\explorer.exe";
/// let size = get_file_size(FILE_PATH).unwrap_or_default();
/// ```
#[allow(unused)]
fn get_file_size(path: &str) -> Option<usize> {
    let mut file_attribute_data: MaybeUninit<WIN32_FILE_ATTRIBUTE_DATA> =
        unsafe { std::mem::MaybeUninit::uninit() };

    let result = unsafe {
        GetFileAttributesExA(
            CString::new(path).unwrap().as_ptr() as _,
            0, /* GetFileExInfoStandard */
            file_attribute_data.as_mut_ptr() as _,
        )
    };

    // Check whether the function failed
    //
    if result == 0 {
        return None;
    }

    // Assume the memory has been initialized
    //
    let file_attribute_data = unsafe { file_attribute_data.assume_init() };

    println!("{:}", file_attribute_data.nFileSizeHigh);
    println!("{:}", file_attribute_data.nFileSizeLow);

    // The low file size is enough for most cases. If you need the high bits too, extract it with the `LARGE_INTEGER` union.
    //
    Some(file_attribute_data.nFileSizeLow as usize)
}

/// Converts the memory to the dos header.
fn get_dos_header(buffer: &mut Vec<u8>) -> Result<*mut IMAGE_DOS_HEADER, DumpError> {
    let dos_header = buffer.as_mut_ptr() as *mut IMAGE_DOS_HEADER;

    if unsafe { (*dos_header).e_magic } != IMAGE_DOS_SIGNATURE {
        Err(DumpError::InvalidDosHeader)
    } else {
        Ok(dos_header)
    }
}

/// Converts the memory to the nt header.
fn get_nt_header(buffer: &mut Vec<u8>) -> Result<*mut IMAGE_NT_HEADERS64, DumpError> {
    let nt_header = buffer.as_mut_ptr() as *mut IMAGE_NT_HEADERS64;

    if unsafe { (*nt_header).Signature } != IMAGE_NT_HEADERS_SIGNATURE
        || unsafe { (*nt_header).OptionalHeader.Magic } != 0x20b
    {
        Err(DumpError::InvalidNtHeader)
    } else {
        Ok(nt_header)
    }
}

/// Returns a byte buffer with the entire image.
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
    let dos_header = get_dos_header(&mut dos_header)?;

    // NT_HEADER
    //
    let mut nt_header = read(
        base + unsafe { (*dos_header).e_lfanew } as usize,
        std::mem::size_of::<IMAGE_NT_HEADERS64>(),
    )
    .ok_or(DumpError::ReadMemory)?;
    let nt_header = get_nt_header(&mut nt_header)?;

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
fn dump_image<R>(base: usize, read: R) -> Result<Vec<u8>, DumpError>
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

fn main() {
    let _base = driver::get_base("win32k.sys").unwrap_or_default();

    // Read
    //
    let context = Context::get_instance();

    let process_id = core::utils::windows::process::by_name("RainbowSix.exe").unwrap();
    context.set_process_id(process_id);
    context.connect().expect("Couldn't connect to the driver.");

    let read = |address, size| context.read_memory::<u8>(address as i64, size).ok();
    let base = context.get_image_base().unwrap();

    let result = dump_image(base as usize, read);

    let mut file: File = File::create("dump.exe").unwrap();
    let _ = file.write(&result.unwrap());

    // if let Ok(image) = result {
    //     let file: PeFile = PeFile::from_bytes(&image).expect("Could not create file");
    //     dbg!(file.imports());
    // }
}
