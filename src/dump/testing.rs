use crate::dump::{get_dos_header, get_nt_header, get_nt_header_new};
use crate::error::DumpError;
use pelite::pe64::{Pe, PeObject};
use winapi::um::winnt::IMAGE_NT_HEADERS64;
use winapi::um::winnt::IMAGE_SECTION_HEADER;

pub(crate) fn dump<R>(base: usize, read: R) -> Option<Vec<u8>>
where
    R: Fn(usize, usize) -> Option<Vec<u8>>,
{
    let mut nt_header = read(base, 0x500)?;
    let nt_header = get_nt_header_new(&mut nt_header).ok()?;
    let image_size = unsafe { (*nt_header).OptionalHeader.SizeOfImage } as usize;

    // Read the buffer
    //
    let mut buffer = Vec::with_capacity(image_size);

    let mut offset = base;
    while offset < image_size {
        let mut temp = read(offset, 0x1000).unwrap_or_else(|| {
            println!("Failed at offset: {:?}", offset - base);

            vec![0; 0x1000]
        });
        buffer.append(&mut temp);

        offset += 0x1000;
    }

    println!("{:?}", buffer.len());

    // let pe = pelite::pe64::PeView::from_bytes(buffer.as_slice()).unwrap();
    //
    // println!("{:?}", pe.align());
    // println!("{:?}", pe.exception());
    // println!("{:?}", pe.exports());
    // println!("{:?}", pe.imports());
    //
    // for i in pe.iat() {
    //     for (a, b) in i.iter() {
    //         println!("{:x?}", b);
    //     }
    // }

    Some(buffer)
    // Some(pe.image().to_vec())
}
