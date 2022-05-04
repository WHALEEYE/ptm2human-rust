use crate::etmv4::*;
use crate::stream::State::{Decoding, Reading, Syncing};
use crate::tracer_etmv4::Etmv4Tracer;

pub struct Stream {
    pub buff: Vec<u8>,
    pub state: State,
    pub tracer: Etmv4Tracer,
}

impl Stream {
    pub fn new() -> Self {
        Self {
            buff: Vec::new(),
            state: Reading,
            tracer: Etmv4Tracer::new(),
        }
    }

    pub fn init_new(&self) -> Self {
        Self {
            buff: Vec::with_capacity(self.buff.len()),
            state: Reading,
            tracer: Etmv4Tracer::new(),
        }
    }
}

#[derive(PartialEq, PartialOrd)]
pub enum State {
    Reading,
    Syncing,
    InSync,
    Decoding,
}

pub fn decode_stream(stream: &mut Stream) {
    let mut cur;

    if stream.state == Reading {
        /* READING -> SYNCING */
        stream.state = Syncing;
    } else {
        eprintln!("Stream state is not correct");
        return;
    }

    println!("Syncing the trace stream...");
    cur = match etmv4_synchronization(stream) {
        Ok(i) => i,
        Err(msg) => {
            eprintln!("{}", msg);
            eprintln!("Cannot find any synchronization packet");
            return;
        }
    };
    println!("Decoding the trace stream...");

    /* INSYNC -> DECODING */
    stream.state = Decoding;
    let mut c;
    while cur < stream.buff.len() {
        c = stream.buff[cur];
        let mut packet = None;
        for tracepkt in &TRACEPKTS {
            if (c & tracepkt.mask) == tracepkt.val {
                packet = Some(tracepkt);
                break;
            }
        }
        if let None = packet {
            eprintln!("Cannot recognize a packet header 0x{:02x}", c);
            eprintln!("Proceed on guesswork");
            cur += 1;
            continue;
        }
        if cur == 79008 {
            println!("123");
        }
        match get_decode_func(packet.unwrap().name).unwrap()(cur, stream) {
            Ok(i) => {
                cur += i;
            }
            Err(msg) => {
                eprintln!("{}", msg);
                eprintln!(
                    "Cannot decode a packet of type {} at offset {}",
                    packet.unwrap().name,
                    cur
                );
                eprintln!("Proceed on guesswork");
                cur += 1;
            }
        }
    }
    println!("Complete decode of the trace stream");
}
