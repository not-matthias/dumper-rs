use crate::error::DumpError;
use pelite::image::{IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS_SIGNATURE};
use winapi::um::winnt::IMAGE_DOS_HEADER;
use winapi::um::winnt::IMAGE_NT_HEADERS64;

pub mod driver;
pub mod pe;
pub mod process;
pub mod testing;

/// Converts the memory to the dos header.
pub fn get_dos_header(buffer: &mut Vec<u8>) -> Result<*mut IMAGE_DOS_HEADER, DumpError> {
    let dos_header = buffer.as_mut_ptr() as *mut IMAGE_DOS_HEADER;

    if unsafe { (*dos_header).e_magic } != IMAGE_DOS_SIGNATURE {
        Err(DumpError::InvalidDosHeader)
    } else {
        Ok(dos_header)
    }
}

/// Converts the memory to the nt header.
pub fn get_nt_header(buffer: &mut Vec<u8>) -> Result<*mut IMAGE_NT_HEADERS64, DumpError> {
    let nt_header = buffer.as_mut_ptr() as *mut IMAGE_NT_HEADERS64;

    if unsafe { (*nt_header).Signature } != IMAGE_NT_HEADERS_SIGNATURE
        || unsafe { (*nt_header).OptionalHeader.Magic } != 0x20b
    {
        Err(DumpError::InvalidNtHeader)
    } else {
        Ok(nt_header)
    }
}

/// Converts the memory to the nt header.
pub fn get_nt_header_new(buffer: &mut Vec<u8>) -> Result<*mut IMAGE_NT_HEADERS64, DumpError> {
    let dos_header = get_dos_header(buffer.as_mut())?;
    let e_lfanew = unsafe { (*dos_header).e_lfanew };

    let nt_header = unsafe { buffer.as_mut_ptr().offset(e_lfanew as _) } as *mut IMAGE_NT_HEADERS64;

    if unsafe { (*nt_header).Signature } != IMAGE_NT_HEADERS_SIGNATURE
        || unsafe { (*nt_header).OptionalHeader.Magic } != 0x20b
    {
        Err(DumpError::InvalidNtHeader)
    } else {
        Ok(nt_header)
    }
}
