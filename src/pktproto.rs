use crate::stream::Stream;

pub type PktHeader = u8;

pub struct TracePkt {
    pub name: &'static str,
    pub mask: PktHeader,
    pub val: PktHeader,
    pub decode: fn(usize, &mut Stream) -> Result<usize, &str>,
}

impl TracePkt {
    pub fn new(name: &'static str, mask: PktHeader, val: PktHeader, decode: fn(usize, &mut Stream) -> Result<usize, &str>) -> Self {
        Self { name, mask, val, decode }
    }
}