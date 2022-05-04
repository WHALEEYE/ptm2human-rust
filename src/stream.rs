use crate::etmv4::*;
use crate::pktproto::TracePkt;
use crate::stream::State::{Decoding, Reading, Syncing};
use crate::tracer_etmv4::Etmv4Tracer;

fn initialize_tracepkts() -> [TracePkt; 56] {
    [
        TracePkt::new("extension", 0xff, 0x00, decode_extension),
        TracePkt::new("trace_info", 0xff, 0x01, decode_trace_info),
        TracePkt::new("trace_on", 0xff, 0x04, decode_trace_on),
        TracePkt::new("timestamp", 0xfe, 0x02, decode_timestamp),
        TracePkt::new("exception", 0xfe, 0x06, decode_exception),
        TracePkt::new("cc_format_1", 0xfe, 0x0e, decode_cc_format_1),
        TracePkt::new("cc_format_2", 0xfe, 0x0c, decode_cc_format_2),
        TracePkt::new("cc_format_3", 0xf0, 0x10, decode_cc_format_3),
        TracePkt::new("data_sync_marker", 0xf0, 0x20, decode_data_sync_marker),
        TracePkt::new("commit", 0xff, 0x2d, decode_commit),
        TracePkt::new("cancel_format_1", 0xfe, 0x2e, decode_cancel_format_1),
        TracePkt::new("cancel_format_2", 0xfc, 0x34, decode_cancel_format_2),
        TracePkt::new("cancel_format_3", 0xf8, 0x38, decode_cancel_format_3),
        TracePkt::new("mispredict", 0xfc, 0x30, decode_mispredict),
        TracePkt::new("cond_inst_format_1", 0xff, 0x6c, decode_cond_inst_format_1),
        TracePkt::new("cond_inst_format_2", 0xfc, 0x40, decode_cond_inst_format_2),
        TracePkt::new("cond_inst_format_3", 0xff, 0x6d, decode_cond_inst_format_3),
        TracePkt::new("cond_flush", 0xff, 0x43, decode_cond_flush),
        TracePkt::new(
            "cond_result_format_1",
            0xf8,
            0x68,
            decode_cond_result_format_1,
        ),
        TracePkt::new(
            "cond_result_format_2",
            0xf8,
            0x48,
            decode_cond_result_format_2,
        ),
        TracePkt::new(
            "cond_result_format_3",
            0xf0,
            0x50,
            decode_cond_result_format_3,
        ),
        TracePkt::new(
            "cond_result_format_4",
            0xfc,
            0x44,
            decode_cond_result_format_4,
        ),
        TracePkt::new("event", 0xf0, 0x70, decode_event),
        TracePkt::new("short_address_is0", 0xff, 0x95, decode_short_address_is0),
        TracePkt::new("short_address_is1", 0xff, 0x96, decode_short_address_is1),
        TracePkt::new(
            "long_address_32bit_is0",
            0xff,
            0x9a,
            decode_long_address_32bit_is0,
        ),
        TracePkt::new(
            "long_address_32bit_is1",
            0xff,
            0x9b,
            decode_long_address_32bit_is1,
        ),
        TracePkt::new(
            "long_address_64bit_is0",
            0xff,
            0x9d,
            decode_long_address_64bit_is0,
        ),
        TracePkt::new(
            "long_address_64bit_is1",
            0xff,
            0x9e,
            decode_long_address_64bit_is1,
        ),
        TracePkt::new(
            "exact_match_address",
            0xfc,
            0x90,
            decode_exact_match_address,
        ),
        TracePkt::new("context", 0xfe, 0x80, decode_context),
        TracePkt::new(
            "address_context_32bit_is0",
            0xff,
            0x82,
            decode_address_context_32bit_is0,
        ),
        TracePkt::new(
            "address_context_32bit_is1",
            0xff,
            0x83,
            decode_address_context_32bit_is1,
        ),
        TracePkt::new(
            "address_context_64bit_is0",
            0xff,
            0x85,
            decode_address_context_64bit_is0,
        ),
        TracePkt::new(
            "address_context_64bit_is1",
            0xff,
            0x86,
            decode_address_context_64bit_is1,
        ),
        TracePkt::new("atom_format_1", 0xfe, 0xf6, decode_atom_format_1),
        TracePkt::new("atom_format_2", 0xfc, 0xd8, decode_atom_format_2),
        TracePkt::new("atom_format_3", 0xf8, 0xf8, decode_atom_format_3),
        TracePkt::new("atom_format_4", 0xfc, 0xdc, decode_atom_format_4),
        TracePkt::new("atom_format_5_1", 0xff, 0xf5, decode_atom_format_5_1),
        TracePkt::new("atom_format_5_2", 0xff, 0xd5, decode_atom_format_5_2),
        TracePkt::new("atom_format_5_3", 0xff, 0xd6, decode_atom_format_5_3),
        TracePkt::new("atom_format_5_4", 0xff, 0xd7, decode_atom_format_5_4),
        TracePkt::new("atom_format_6_1", 0xff, 0xd0, decode_atom_format_6_1),
        TracePkt::new("atom_format_6_2", 0xff, 0xd1, decode_atom_format_6_2),
        TracePkt::new("atom_format_6_3", 0xff, 0xd2, decode_atom_format_6_3),
        TracePkt::new("atom_format_6_4", 0xff, 0xd3, decode_atom_format_6_4),
        TracePkt::new("atom_format_6_5", 0xff, 0xd4, decode_atom_format_6_5),
        TracePkt::new("atom_format_6_6", 0xff, 0xf0, decode_atom_format_6_6),
        TracePkt::new("atom_format_6_7", 0xff, 0xf1, decode_atom_format_6_7),
        TracePkt::new("atom_format_6_8", 0xff, 0xf2, decode_atom_format_6_8),
        TracePkt::new("atom_format_6_9", 0xff, 0xf3, decode_atom_format_6_9),
        TracePkt::new("atom_format_6_10", 0xff, 0xf4, decode_atom_format_6_10),
        TracePkt::new("atom_format_6_11", 0xf0, 0xc0, decode_atom_format_6_11),
        TracePkt::new("atom_format_6_12", 0xf0, 0xe0, decode_atom_format_6_12),
        TracePkt::new("q", 0xf0, 0xa0, decode_q),
    ]
}

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
    Decoded,
}

pub fn decode_stream(stream: &mut Stream) {
    let tracepkts = initialize_tracepkts();
    let mut cur: usize;
    let mut i: usize;

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
    while cur < stream.buff.len() {
        let c: u8 = stream.buff[cur];
        i = 0;
        while i < tracepkts.len() {
            if (c & tracepkts[i].mask) == tracepkts[i].val {
                break;
            }
            i += 1;
        }
        if i == tracepkts.len() {
            eprintln!("Cannot recognize a packet header 0x{:02x}", c);
            eprintln!("Proceed on guesswork");
            cur += 1;
            continue;
        }
        match (tracepkts[i].decode)(cur, stream) {
            Ok(i) => {
                cur += i;
            }
            Err(msg) => {
                eprintln!("{}", msg);
                eprintln!(
                    "Cannot decode a packet of type {} at offset {}",
                    tracepkts[i].name, cur
                );
                eprintln!("Proceed on guesswork");
                cur += 1;
            }
        }
    }
    println!("Complete decode of the trace stream");
}
