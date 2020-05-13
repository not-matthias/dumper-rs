use context::context;
use core::driver::context::DriverOperations;
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
    let process_id = core::utils::windows::process::by_name(name).ok()?;
    context::set_process_id(process_id as _);

    let context = core::driver::context::Context::get_instance();
    context.set_process_id(process_id);
    context.connect().expect("Failed to connect to driver.");

    // Dump the image
    //
    let read = |address, size| context.read_memory::<u8>(address, size).ok();
    // let read = |address, size| context::read_list::<u8>(address, size).ok();
    let base = context.get_image_base().unwrap();

    let result = dump::process::dump(base as usize, read).ok()?;

    // Save the image to disk
    //
    let mut file: File = File::create(file_name).ok()?;
    let _ = file.write(&result);

    Some(())
}

/// Dumps the specified driver and stores it on disk.
#[allow(dead_code)]
fn dump_driver(name: &str, file_name: &str) -> Option<()> {
    // Setup the context
    //
    // let process_id = core::utils::windows::process::by_name("explorer.exe").ok()?;
    context::set_process_id(4 as _);

    let context = core::driver::context::Context::get_instance();
    context.set_process_id(4);
    context.connect().unwrap();

    // let memory = context.read_memory::<u8>(0xfffff801cb9901e0, 0x28);
    // println!("{:x?}", memory);

    // Dump the image
    //
    let read = |address, size| context.read_memory::<u8>(address, size).ok();
    let base = utils::driver::get_base(name)?;
    println!("Base address is {:x?}.", base);

    let result = dump::driver::dump(base as usize, read).ok()?;

    // Save the image to disk
    //
    let mut file: File = File::create(file_name).ok()?;
    let _ = file.write(&result);

    Some(())
}

fn main() {
    dump_driver("Null", "dump.sys");
    // dump_process("explorer.exe", "dump.exe").unwrap();
}
