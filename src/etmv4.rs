use crate::stream::State::InSync;
use crate::stream::{State, Stream};
use crate::tracer_etmv4::{
    reset_address_register, tracer_discard, tracer_overflow, tracer_trace_info, tracer_trace_on,
};

const C_BIT: u8 = 0x80;

pub fn decode_extension(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    let mut index: usize = 1;
    let mut cnt;
    match { stream.buff[header_index + index] } {
        0 => {
            /* async */
            cnt = 0;
            while (cnt < 11) && (index < stream.buff.len()) {
                if cnt == 10 && stream.buff[header_index + index] != 0x80 {
                    break;
                }
                if cnt != 10 && stream.buff[header_index + index] != 0 {
                    break;
                }
                cnt += 1;
                index += 1;
            }
            if cnt != 11 {
                return Err("Invalid async packet: Payload bytes of async are not correct");
            }
        }
        3 => {
            /* discard */
            index += 1;
            tracer_discard(&stream.tracer);
        }
        5 => {
            /* overflow */
            index += 1;
            tracer_overflow(&stream.tracer);
        }
        _ => {
            return Err("Invalid async packet: First payload byte of async is not correct");
        }
    }
    return Ok(index);
}

pub fn decode_trace_info(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    let mut index = 1;
    let mut i;
    let mut plctl: u32 = 0;
    let mut info: u32 = 0;
    let mut key: u32 = 0;
    let mut spec: u32 = 0;
    let mut cyct: u32 = 0;
    let mut data: u8;

    /* TODO: refactor the following code into a reusable function */
    i = 0;
    while i < 4 {
        data = stream.buff[header_index + index];
        index += 1;
        plctl |= ((data & !C_BIT) as u32) << (7 * i);
        if (data & C_BIT) == 0 {
            break;
        }
        i += 1;
    }
    if i >= 1 {
        return Err("More than 1 PLCTL field in the trace info packet");
    }

    if (plctl & 1) != 0 {
        i = 0;
        /* the INFO section is present*/
        while i < 4 {
            data = stream.buff[header_index + index];
            index += 1;
            info |= ((data & !C_BIT) as u32) << (7 * i);
            if (data & C_BIT) == 0 {
                break;
            }
        }
        if i >= 1 {
            return Err("More than 1 INFO field in the trace info packet");
        }
    }

    if (plctl & 2) != 0 {
        /* the KEY section is present*/
        i = 0;
        while i < 4 {
            data = stream.buff[header_index + index];
            index += 1;
            key |= ((data & !C_BIT) as u32) << (7 * i);
            if (data & C_BIT) == 0 {
                break;
            }
            i += 1;
        }
        if i >= 4 {
            /* 4 fileds are enough since p0_key_max is a 32-bit integer */
            return Err("More than 4 KEY fields in the trace info packet");
        }
    }

    if (plctl & 4) != 0 {
        /* the SPEC section is present*/
        i = 0;
        while i < 4 {
            data = stream.buff[header_index + index];
            index += 1;
            spec |= ((data & !C_BIT) as u32) << (7 * i);
            if (data & C_BIT) == 0 {
                break;
            }
        }
        if i >= 4 {
            /* 4 fileds are enough since max_spec_depth is a 32-bit integer */
            return Err("More than 4 SPEC fields in the trace info packet");
        }
    }

    if (plctl & 8) != 0 {
        /* the CYCT section is present*/
        i = 0;
        while i < 2 {
            data = stream.buff[header_index + index];
            index += 1;
            cyct |= ((data & !C_BIT) as u32) << (7 * i);
            if (data & C_BIT) == 0 {
                break;
            }
        }
        if i >= 2 {
            return Err("More than 2 CYCT fields in the trace info packet\n");
        }
    }

    if stream.state >= State::InSync {
        tracer_trace_info(&mut stream.tracer, plctl, info, key, spec, cyct);
    }

    return Ok(index);
}

pub fn decode_trace_on(_: usize, stream: &mut Stream) -> Result<usize, &str> {
    tracer_trace_on(&stream.tracer);
    return Ok(1);
}

pub fn decode_timestamp(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_exception(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_cc_format_1(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_cc_format_2(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_cc_format_3(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_data_sync_marker(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_commit(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_cancel_format_1(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_cancel_format_2(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_cancel_format_3(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_mispredict(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_cond_inst_format_1(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_cond_inst_format_2(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_cond_inst_format_3(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_cond_flush(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_cond_result_format_1(
    header_index: usize,
    stream: &mut Stream,
) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_cond_result_format_2(
    header_index: usize,
    stream: &mut Stream,
) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_cond_result_format_3(
    header_index: usize,
    stream: &mut Stream,
) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_cond_result_format_4(
    header_index: usize,
    stream: &mut Stream,
) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_event(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_short_address_is0(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_short_address_is1(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_long_address_32bit_is0(
    header_index: usize,
    stream: &mut Stream,
) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_long_address_32bit_is1(
    header_index: usize,
    stream: &mut Stream,
) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_long_address_64bit_is0(
    header_index: usize,
    stream: &mut Stream,
) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_long_address_64bit_is1(
    header_index: usize,
    stream: &mut Stream,
) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_exact_match_address(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_context(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_address_context_32bit_is0(
    header_index: usize,
    stream: &mut Stream,
) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_address_context_32bit_is1(
    header_index: usize,
    stream: &mut Stream,
) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_address_context_64bit_is0(
    header_index: usize,
    stream: &mut Stream,
) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_address_context_64bit_is1(
    header_index: usize,
    stream: &mut Stream,
) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_atom_format_1(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_atom_format_2(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_atom_format_3(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_atom_format_4(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_atom_format_5_1(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_atom_format_5_2(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_atom_format_5_3(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_atom_format_5_4(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_atom_format_6_1(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_atom_format_6_2(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_atom_format_6_3(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_atom_format_6_4(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_atom_format_6_5(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_atom_format_6_6(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_atom_format_6_7(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_atom_format_6_8(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_atom_format_6_9(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_atom_format_6_10(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_atom_format_6_11(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_atom_format_6_12(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}
pub fn decode_q(header_index: usize, stream: &mut Stream) -> Result<usize, &str> {
    return Ok(0);
}

const EXTENSION_PACKET_MASK: u8 = 0xff;
const EXTENSION_PACKET_VAL: u8 = 0x00;
const TRACE_INFO_PACKET_MASK: u8 = 0xff;
const TRACE_INFO_PACKET_VAL: u8 = 0x01;

pub fn etmv4_synchronization(stream: &mut Stream) -> Result<usize, &str> {
    let mut c: u8;
    for i in 0..stream.buff.len() {
        c = stream.buff[i];
        if c & EXTENSION_PACKET_MASK == EXTENSION_PACKET_VAL {
            match decode_extension(i, stream) {
                Ok(p) => {
                    if p != 12 {
                        continue;
                    }
                }
                Err(msg) => {
                    eprintln!("{}", msg);
                    continue;
                }
            };
            c = stream.buff[i + 12];
            if (c & TRACE_INFO_PACKET_MASK) == TRACE_INFO_PACKET_VAL {
                match decode_trace_info(i + 12, stream) {
                    Ok(p) => {
                        /* SYNCING -> INSYNC */
                        stream.state = InSync;
                        reset_address_register(&mut stream.tracer);
                        return Ok(i);
                    }
                    Err(msg) => {
                        eprintln!("{}", msg);
                    }
                };
            }
        }
    }
    /*
     * If reach here, there is no trace info packet found.
     * According to IHI0064C_etm_v4_architecture_spec:
     * ARM recommends that the Trace Info packet appears in the trace
     * stream soon after the A-Sync packet.
     */
    return Err("No trace info packet right after an a-sync packet");
}
