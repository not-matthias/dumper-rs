#[derive(Debug)]
pub enum DumpError {
    ImageBase,
    ReadMemory,
    InvalidDosHeader,
    InvalidNtHeader,
}
