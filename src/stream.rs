use crate::tracer_etmv4::{self, Etmv4Tracer};

pub struct Stream {
    pub buff: Vec<u8>,
    pub buff_len: u32,
    pub state: State,
    pub tracer: tracer_etmv4::Etmv4Tracer,
}

impl Stream {
    pub fn new() -> Self {
        Self {
            buff: Vec::new(),
            buff_len: 0,
            state: State::READING,
            tracer: Etmv4Tracer::new(),
        }
    }
}

pub enum State {
    READING,
    SYNCING,
    INSYNC,
    DECODING,
    DECODED,
}

