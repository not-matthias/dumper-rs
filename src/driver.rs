use ntapi::ntexapi::NtQuerySystemInformation;
use ntapi::ntldr::RTL_PROCESS_MODULES;
use ntapi::ntldr::RTL_PROCESS_MODULE_INFORMATION;
use std::ffi::CStr;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::memoryapi::VirtualAlloc;
use winapi::um::winnt::MEM_COMMIT;
use winapi::um::winnt::MEM_RESERVE;
use winapi::um::winnt::PAGE_READWRITE;

/// Finds the base address of the specified driver name.
///
/// # Parameter
/// - `driver`: Substring of the driver name. The first match will be returned.
pub fn get_base<T: AsRef<str>>(driver: T) -> Option<usize> {
    // Allocate memory for the modules
    //
    let buffer: *mut RTL_PROCESS_MODULES = unsafe {
        VirtualAlloc(
            std::ptr::null_mut(),
            1024 * 1024,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    } as _;

    if unsafe { GetLastError() } != 0 {
        return None;
    }

    // Query the system information
    //
    let status =
        unsafe { NtQuerySystemInformation(11, buffer as _, 1024 * 1024, std::ptr::null_mut()) };

    if status == 1 && unsafe { GetLastError() } != 0 {
        return None;
    }

    // Loop over all drivers
    //
    for i in 0..unsafe { (*buffer).NumberOfModules as isize } {
        let module: *mut RTL_PROCESS_MODULE_INFORMATION =
            unsafe { (*buffer).Modules.as_mut_ptr().offset(i) as _ };

        // Check whether the module is valid
        //
        if unsafe { (*module).ImageBase } == std::ptr::null_mut() {
            continue;
        }

        // Convert the driver name
        //
        let image_name = unsafe {
            CStr::from_ptr((*module).FullPathName.as_mut_ptr() as _)
                .to_str()
                .unwrap_or_default()
        };

        // Check if the name matches
        //
        if image_name.contains(driver.as_ref()) {
            return Some(unsafe { (*module).ImageBase as _ });
        }
    }

    None
}
