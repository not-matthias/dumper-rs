use std::ffi::CString;
use winapi::um::fileapi::GetFileAttributesExA;
use winapi::um::fileapi::WIN32_FILE_ATTRIBUTE_DATA;

pub mod driver;
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
    let mut file_attribute_data: std::mem::MaybeUninit<WIN32_FILE_ATTRIBUTE_DATA> =
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

    // The low file size is enough for most cases. If you need the high bits too, extract it with the `LARGE_INTEGER` union.
    //
    Some(file_attribute_data.nFileSizeLow as usize)
}
