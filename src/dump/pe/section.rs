use winapi::um::winnt::IMAGE_SECTION_HEADER;

pub struct Section {
    /// The memory of the section header.
    pub(crate) header_memory: Vec<u8>,

    /// The section header.
    pub(crate) header: IMAGE_SECTION_HEADER,

    /// The section content.
    pub(crate) content: Vec<u8>,
}
