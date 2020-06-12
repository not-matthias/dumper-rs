use crate::error::DumpError;
use context::context;
use std::fs::File;
use std::io::Write;

pub mod dump;
pub mod error;
pub mod utils;

/// Dumps the specified process and stores it on disk.
#[allow(dead_code)]
fn dump_process(name: &str, file_name: &str) -> Option<()> {
    // Setup the context
    //
    let process_id = windows::process::by_name(name).ok()?;
    context::set_process_id(process_id as _);

    // Dump the image
    //
    let read = |address, size| context::read_list::<u8>(address, size).ok();
    let base = context::get_image_base().unwrap();

    let result = dump::process::dump(base as usize, read).ok()?;

    // Save the image to disk
    //
    let mut file: File = File::create(file_name).ok()?;
    let _ = file.write(&result);

    Some(())
}

/// Dumps the specified driver and stores it on disk.
#[allow(dead_code)]
fn dump_driver(name: &str, file_name: &str) -> Result<(), DumpError> {
    // Setup the context
    //
    // let process_id = core::utils::windows::process::by_name("explorer.exe").ok()?;
    context::set_process_id(4 as _);

    context::set_process_id(4);
    context::connect().unwrap();

    // Dump the image
    //
    let read = |address, size| context::read_list::<u8>(address, size).ok();
    let base = utils::driver::get_base(name).ok_or(DumpError::ImageBase)?;
    println!("Base address is {:x?}.", base);

    println!("{:x?}", context::read_list::<u8>(base, 4));

    // let result = dump::testing::dump(base, read).unwrap();
    // println!("{:x?}", result);

    let result = dump::driver::dump(base as usize, read)?;
    println!("{:x?}", result);

    // Save the image to disk
    //
    println!("Saving the driver to disk.");
    let mut file: File = File::create(file_name).unwrap();
    let _ = file.write(&result);

    Ok(())
}

fn main() {
    println!("{:?}", dump_driver("BEDaisy", "dump.sys"));
    // dump_process("explorer.exe", "dump.exe").unwrap();
}
