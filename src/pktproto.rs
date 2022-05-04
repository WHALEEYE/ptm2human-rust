pub type PktHeader = u8;

pub struct TracePkt {
    pub name: &'static str,
    pub mask: PktHeader,
    pub val: PktHeader,
}

impl TracePkt {
    pub const fn new(name: &'static str, mask: PktHeader, val: PktHeader) -> Self {
        Self { name, mask, val }
    }
}
