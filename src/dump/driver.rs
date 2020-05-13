use crate::dump::pe::module::Module;
use crate::error::DumpError;

#[allow(dead_code)]
pub(crate) fn dump<R>(base: usize, read: R) -> Result<Vec<u8>, DumpError>
where
    R: Fn(usize, usize) -> Option<Vec<u8>>,
{
    let mut module = Module::new(base);

    module.dump(read)?;
    module.align_sections().unwrap();
    module.fix_header().unwrap();

    Ok(module.get_buffer())
}
