use crate::pktproto::TracePkt;
use crate::stream::State::InSync;
use crate::stream::{State, Stream};
use crate::tracer_etmv4::{AddrReg::*, AtomType::*, *};

const C_BIT: u8 = 0x80;

pub fn get_decode_func(
    pkt_name: &str,
) -> Option<fn(pkt_offset: usize, stream: &mut Stream) -> Result<usize, &str>> {
    match pkt_name {
        "extension" => Some(decode_extension),
        "trace_info" => Some(decode_trace_info),
        "trace_on" => Some(decode_trace_on),
        "timestamp" => Some(decode_timestamp),
        "exception" => Some(decode_exception),
        "cc_format_1" => Some(decode_cc_format_1),
        "cc_format_2" => Some(decode_cc_format_2),
        "cc_format_3" => Some(decode_cc_format_3),
        "data_sync_marker" => Some(decode_data_sync_marker),
        "commit" => Some(decode_commit),
        "cancel_format_1" | "cancel_format_2" | "cancel_format_3" => Some(decode_cancel),
        "mispredict" => Some(decode_mispredict),
        "cond_inst_format_1" => Some(decode_cond_inst_format_1),
        "cond_inst_format_2" => Some(decode_cond_inst_format_2),
        "cond_inst_format_3" => Some(decode_cond_inst_format_3),
        "cond_flush" => Some(decode_cond_flush),
        "cond_result_format_1" => Some(decode_cond_result_format_1),
        "cond_result_format_2" => Some(decode_cond_result_format_2),
        "cond_result_format_3" => Some(decode_cond_result_format_3),
        "cond_result_format_4" => Some(decode_cond_result_format_4),
        "event" => Some(decode_event),
        "short_address_is0" | "short_address_is1" => Some(decode_short_address),
        "long_address_32bit_is0"
        | "long_address_32bit_is1"
        | "long_address_64bit_is0"
        | "long_address_64bit_is1" => Some(decode_long_address),
        "exact_match_address" => Some(decode_exact_match_address),
        "context" => Some(decode_context),
        "address_context_32bit_is0"
        | "address_context_32bit_is1"
        | "address_context_64bit_is0"
        | "address_context_64bit_is1" => Some(decode_address_context),
        "atom_format_1" => Some(decode_atom_format_1),
        "atom_format_2" => Some(decode_atom_format_2),
        "atom_format_3" => Some(decode_atom_format_3),
        "atom_format_4" => Some(decode_atom_format_4),
        "atom_format_5_1" | "atom_format_5_2" | "atom_format_5_3" | "atom_format_5_4" => {
            Some(decode_atom_format_5)
        }
        "atom_format_6_1" | "atom_format_6_2" | "atom_format_6_3" | "atom_format_6_4"
        | "atom_format_6_5" | "atom_format_6_6" | "atom_format_6_7" | "atom_format_6_8"
        | "atom_format_6_9" | "atom_format_6_10" | "atom_format_6_11" | "atom_format_6_12" => {
            Some(decode_atom_format_6)
        }
        "q" => Some(decode_q),
        _ => None,
    }
}

pub fn decode_extension(pkt_offset: usize, stream: &mut Stream) -> Result<usize, &str> {
    let mut index = 1;
    let mut cnt;
    match { stream.buff[pkt_offset + index] } {
        0 => {
            /* async */
            cnt = 0;
            while (cnt < 11) && (index < stream.buff.len()) {
                if cnt == 10 && stream.buff[pkt_offset + index] != 0x80 {
                    break;
                }
                if cnt != 10 && stream.buff[pkt_offset + index] != 0 {
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

pub fn decode_trace_info(pkt_offset: usize, stream: &mut Stream) -> Result<usize, &str> {
    let mut index = 1;
    let mut i;
    let mut plctl = 0;
    let mut info = 0;
    let mut key = 0;
    let mut spec = 0;
    let mut cyct = 0;
    let mut data;

    /* TODO: refactor the following code into a reusable function */
    i = 0;
    while i < 4 {
        data = stream.buff[pkt_offset + index];
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
            data = stream.buff[pkt_offset + index];
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
            data = stream.buff[pkt_offset + index];
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
            data = stream.buff[pkt_offset + index];
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
            data = stream.buff[pkt_offset + index];
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

pub fn decode_timestamp(pkt_offset: usize, stream: &mut Stream) -> Result<usize, &str> {
    let mut index = 1;
    let mut nr_replace = 0;
    let mut ts = 0;
    let mut data;
    let mut count = 0;

    let mut i = 0;
    while index < 10 {
        data = stream.buff[pkt_offset + index];
        index += 1;
        ts |= ((data & !C_BIT) as u64) << (7 * i);
        if index != 9 {
            nr_replace += 7;
        } else {
            nr_replace += 8;
        }
        if (index != 9) && (data & C_BIT) == 0 {
            break;
        }
        i += 1;
    }

    if (stream.buff[pkt_offset] & 1) != 0 {
        /* cycle count section is present since the N bit in the header is 1'b1 */
        for i in 0..3 {
            data = stream.buff[pkt_offset + index];
            index += 1;
            count |= ((data & !C_BIT) as u32) << (7 * i);
            if (data & C_BIT) == 0 {
                break;
            }
        }
    }

    tracer_ts(
        &mut stream.tracer,
        ts,
        (stream.buff[pkt_offset] & 1) != 0,
        count,
        nr_replace,
    );

    return Ok(index);
}
pub fn decode_exception(pkt_offset: usize, stream: &mut Stream) -> Result<usize, &str> {
    let mut index = 1;
    let ee;
    let tp;
    let mut data1;
    let mut data2 = 0;

    if (stream.buff[pkt_offset] & 1) != 0 {
        /* exception return packet */
        tracer_exception_return(&stream.tracer);
    } else {
        /* exception patcket */
        data1 = stream.buff[pkt_offset + index];
        index += 1;
        if (data1 & C_BIT) != 0 {
            data2 = stream.buff[pkt_offset + index];
            index += 1;
        }
        ee = ((data1 & 0x40) >> 5) | (data1 & 0x01);
        tp = ((data1 & 0x3E) >> 1) | (data2 & 0x1F);

        if ee != 1 && ee != 2 {
            return Err("Invalid EE in the exception packet");
        } else if ee == 2 {
            /* there is an address packet */
            data1 = stream.buff[pkt_offset + index];
            let mut packet = None;
            for tracepkt in &TRACEPKTS {
                if (data1 & tracepkt.mask) == tracepkt.val {
                    packet = Some(tracepkt);
                    break;
                }
            }
            if let Some(pkt) = packet {
                match get_decode_func(pkt.name).unwrap()(index + pkt_offset, stream) {
                    Ok(idx) => {
                        index += idx;
                    }
                    Err(msg) => {
                        eprintln!("{}", msg);
                        return Err("Invalid address packet in the exception packet");
                    }
                }
            } else {
                return Err("Invalid address packet in the exception packet");
            }
        }
        tracer_exception(&mut stream.tracer, tp as usize);
    }
    return Ok(index);
}

pub fn decode_cc_format_1(_: usize, _: &mut Stream) -> Result<usize, &str> {
    unimplemented!()
}

pub fn decode_cc_format_2(_: usize, _: &mut Stream) -> Result<usize, &str> {
    unimplemented!()
}

pub fn decode_cc_format_3(_: usize, _: &mut Stream) -> Result<usize, &str> {
    unimplemented!()
}

pub fn decode_data_sync_marker(_: usize, _: &mut Stream) -> Result<usize, &str> {
    unimplemented!()
}

pub fn decode_commit(_: usize, _: &mut Stream) -> Result<usize, &str> {
    unimplemented!()
}

pub fn decode_cancel(_: usize, _: &mut Stream) -> Result<usize, &str> {
    unimplemented!()
}

pub fn decode_mispredict(_: usize, _: &mut Stream) -> Result<usize, &str> {
    unimplemented!()
}

pub fn decode_cond_inst_format_1(_: usize, _: &mut Stream) -> Result<usize, &str> {
    unimplemented!()
}
pub fn decode_cond_inst_format_2(_: usize, _: &mut Stream) -> Result<usize, &str> {
    unimplemented!()
}
pub fn decode_cond_inst_format_3(_: usize, _: &mut Stream) -> Result<usize, &str> {
    unimplemented!()
}
pub fn decode_cond_flush(_: usize, _: &mut Stream) -> Result<usize, &str> {
    unimplemented!()
}
pub fn decode_cond_result_format_1(_: usize, _: &mut Stream) -> Result<usize, &str> {
    unimplemented!()
}
pub fn decode_cond_result_format_2(_: usize, _: &mut Stream) -> Result<usize, &str> {
    unimplemented!()
}
pub fn decode_cond_result_format_3(_: usize, _: &mut Stream) -> Result<usize, &str> {
    unimplemented!()
}
pub fn decode_cond_result_format_4(_: usize, _: &mut Stream) -> Result<usize, &str> {
    unimplemented!()
}
pub fn decode_event(_: usize, _: &mut Stream) -> Result<usize, &str> {
    unimplemented!()
}

fn update_address_regs(stream: &mut Stream, address: u64, is: AddrReg) {
    stream.tracer.address_register[2] = stream.tracer.address_register[1];
    stream.tracer.address_register[1] = stream.tracer.address_register[0];
    stream.tracer.address_register[0].address = address;
    stream.tracer.address_register[0].is = is;
}

pub fn decode_short_address(pkt_offset: usize, stream: &mut Stream) -> Result<usize, &str> {
    let mut index = 1;
    let mut address = stream.tracer.address_register[0].address;
    let is;

    if (stream.buff[pkt_offset] & 0x01) != 0 {
        is = AddrRegIs0;
        address &= !0x000001FF;
        address |= ((stream.buff[pkt_offset + index] as u64) & 0x7F) << 2;
        index += 1;
        if (stream.buff[pkt_offset + 1] & C_BIT) != 0 {
            address &= !0x0001FE00;
            address |= (stream.buff[pkt_offset + index] as u64) << 9;
            index += 1;
        }
    } else {
        is = AddrRegIs1;
        address &= !0x000000FF;
        address |= ((stream.buff[pkt_offset + index] as u64) & 0x7F) << 1;
        index += 1;
        if (stream.buff[pkt_offset + 1] & C_BIT) != 0 {
            address &= !0x0000FF00;
            address &= (stream.buff[pkt_offset + index] as u64) << 8;
            index += 1;
        }
    }

    update_address_regs(stream, address, is);

    tracer_address(&stream.tracer);

    return Ok(index);
}

pub fn decode_long_address(pkt_offset: usize, stream: &mut Stream) -> Result<usize, &str> {
    let mut index = 1;
    let is;
    let mut address;

    address = stream.tracer.address_register[0].address;

    match stream.buff[pkt_offset] {
        0x9a => {
            is = AddrRegIs0;
            address &= !0xFFFFFFFF;
            address |= ((stream.buff[pkt_offset + index] & 0x7F) as u64) << 2;
            index += 1;
            address |= ((stream.buff[pkt_offset + index] & 0x7F) as u64) << 9;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 16;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 24;
            index += 1;
        }
        0x9b => {
            is = AddrRegIs1;
            address &= !0xFFFFFFFF;
            address |= ((stream.buff[pkt_offset + index] & 0x7F) as u64) << 1;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 8;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 16;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 24;
            index += 1;
        }
        0x9d => {
            is = AddrRegIs0;
            address = 0;
            address |= ((stream.buff[pkt_offset + index] & 0x7F) as u64) << 2;
            index += 1;
            address |= ((stream.buff[pkt_offset + index] & 0x7F) as u64) << 9;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 16;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 24;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 32;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 40;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 48;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 56;
            index += 1;
        }
        0x9e => {
            is = AddrRegIs1;
            address = 0;
            address |= ((stream.buff[pkt_offset + index] as u64) & 0x7F) << 1;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 8;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 16;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 24;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 32;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 40;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 48;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 56;
            index += 1;
        }
        _ => {
            return Err("");
        }
    }

    update_address_regs(stream, address, is);
    tracer_address(&stream.tracer);
    return Ok(index);
}

pub fn decode_exact_match_address(pkt_offset: usize, stream: &mut Stream) -> Result<usize, &str> {
    let qe = (stream.buff[pkt_offset] & 0x03) as usize;
    update_address_regs(
        stream,
        stream.tracer.address_register[qe].address,
        stream.tracer.address_register[qe].is,
    );
    tracer_address(&stream.tracer);
    return Ok(1);
}

pub fn decode_context(pkt_offset: usize, stream: &mut Stream) -> Result<usize, &str> {
    let mut index = 0;
    let mut el = 0;
    let mut sf = 0;
    let mut ns = 0;
    let mut v = 0;
    let mut c = 0;
    let mut vmid = 0;
    let mut contextid = 0;

    let mut data = stream.buff[pkt_offset + index];
    index += 1;
    if (data & 1) != 0 {
        data = stream.buff[pkt_offset + index];
        index += 1;
        el = data & 0x3;
        sf = (data & 0x10) >> 4;
        ns = (data & 0x20) >> 5;
        if (data & 0x40) != 0 {
            v = 1;
            vmid = stream.buff[pkt_offset + index];
            index += 1;
        }
        if (data & 0x80) != 0 {
            c = 1;
            contextid = stream.buff[pkt_offset + index] as u32;
            index += 1;
            contextid |= (stream.buff[pkt_offset + index] as u32) << 8;
            index += 1;
            contextid |= (stream.buff[pkt_offset + index] as u32) << 16;
            index += 1;
            contextid |= (stream.buff[pkt_offset + index] as u32) << 24;
            index += 1;
        }
    }

    tracer_context(
        &mut stream.tracer,
        stream.buff[pkt_offset] & 1,
        el,
        sf,
        ns,
        v,
        vmid,
        c,
        contextid,
    );

    return Ok(index);
}

pub fn decode_address_context(pkt_offset: usize, stream: &mut Stream) -> Result<usize, &str> {
    let mut index = 1;
    let is;
    let el;
    let sf;
    let ns;
    let mut v = 0;
    let mut c = 0;
    let data;
    let mut vmid = 0;
    let mut contextid = 0;

    let mut address = stream.tracer.address_register[0].address;

    match stream.buff[pkt_offset] {
        0x82 => {
            is = AddrRegIs0;
            address &= !0xFFFFFFFF;
            address |= ((stream.buff[pkt_offset + index] & 0x7F) as u64) << 2;
            index += 1;
            address |= ((stream.buff[pkt_offset + index] & 0x7F) as u64) << 9;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 16;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 24;
            index += 1;
        }
        0x83 => {
            is = AddrRegIs1;
            address &= !0xFFFFFFFF;
            address |= ((stream.buff[pkt_offset + index] & 0x7F) as u64) << 1;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 8;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 16;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 24;
            index += 1;
        }
        0x85 => {
            is = AddrRegIs0;
            address = 0;
            address |= ((stream.buff[pkt_offset + index] & 0x7F) as u64) << 2;
            index += 1;
            address |= ((stream.buff[pkt_offset + index] & 0x7F) as u64) << 9;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 16;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 24;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 32;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 40;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 48;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 56;
            index += 1;
        }
        0x86 => {
            is = AddrRegIs1;
            address = 0;
            address |= ((stream.buff[pkt_offset + index] & 0x7F) as u64) << 1;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 8;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 16;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 24;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 32;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 40;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 48;
            index += 1;
            address |= (stream.buff[pkt_offset + index] as u64) << 56;
            index += 1;
        }
        _ => {
            return Err("");
        }
    }
    update_address_regs(stream, address, is);

    data = stream.buff[pkt_offset + index];
    index += 1;
    el = data & 0x3;
    sf = (data & 0x10) >> 4;
    ns = (data & 0x20) >> 5;
    if (data & 0x40) != 0 {
        v = 1;
        vmid = stream.buff[pkt_offset + index];
        index += 1;
    }
    if (data & 0x80) != 0 {
        c = 1;
        contextid = stream.buff[pkt_offset + index] as u32;
        index += 1;
        contextid |= (stream.buff[pkt_offset + index] as u32) << 8;
        index += 1;
        contextid |= (stream.buff[pkt_offset + index] as u32) << 16;
        index += 1;
        contextid |= (stream.buff[pkt_offset + index] as u32) << 24;
        index += 1;
    }

    tracer_context(&mut stream.tracer, 1, el, sf, ns, v, vmid, c, contextid);
    tracer_address(&stream.tracer);

    return Ok(index);
}

pub fn decode_atom_format_1(pkt_offset: usize, stream: &mut Stream) -> Result<usize, &str> {
    let a = stream.buff[pkt_offset] & 0x01;
    tracer_atom(
        &mut stream.tracer,
        if a != 0 { AtomTypeE } else { AtomTypeN },
    );
    return Ok(1);
}

pub fn decode_atom_format_2(pkt_offset: usize, stream: &mut Stream) -> Result<usize, &str> {
    let a = stream.buff[pkt_offset] & 0x03;

    tracer_atom(
        &mut stream.tracer,
        if (a & 1) != 0 { AtomTypeE } else { AtomTypeN },
    );
    tracer_atom(
        &mut stream.tracer,
        if (a & 2) != 0 { AtomTypeE } else { AtomTypeN },
    );
    return Ok(1);
}

pub fn decode_atom_format_3(pkt_offset: usize, stream: &mut Stream) -> Result<usize, &str> {
    let a = stream.buff[pkt_offset] & 0x07;

    tracer_atom(
        &mut stream.tracer,
        if (a & 1) != 0 { AtomTypeE } else { AtomTypeN },
    );
    tracer_atom(
        &mut stream.tracer,
        if (a & 2) != 0 { AtomTypeE } else { AtomTypeN },
    );
    tracer_atom(
        &mut stream.tracer,
        if (a & 4) != 0 { AtomTypeE } else { AtomTypeN },
    );
    return Ok(1);
}
pub fn decode_atom_format_4(pkt_offset: usize, stream: &mut Stream) -> Result<usize, &str> {
    let a = stream.buff[pkt_offset] & 0x03;

    match a {
        0 => {
            tracer_atom(&mut stream.tracer, AtomTypeN);
            tracer_atom(&mut stream.tracer, AtomTypeE);
            tracer_atom(&mut stream.tracer, AtomTypeE);
            tracer_atom(&mut stream.tracer, AtomTypeE);
        }
        1 => {
            tracer_atom(&mut stream.tracer, AtomTypeN);
            tracer_atom(&mut stream.tracer, AtomTypeN);
            tracer_atom(&mut stream.tracer, AtomTypeN);
            tracer_atom(&mut stream.tracer, AtomTypeN);
        }
        2 => {
            tracer_atom(&mut stream.tracer, AtomTypeN);
            tracer_atom(&mut stream.tracer, AtomTypeE);
            tracer_atom(&mut stream.tracer, AtomTypeN);
            tracer_atom(&mut stream.tracer, AtomTypeE);
        }
        3 => {
            tracer_atom(&mut stream.tracer, AtomTypeE);
            tracer_atom(&mut stream.tracer, AtomTypeN);
            tracer_atom(&mut stream.tracer, AtomTypeE);
            tracer_atom(&mut stream.tracer, AtomTypeN);
        }
        _ => {}
    }
    return Ok(1);
}

pub fn decode_atom_format_5(pkt_offset: usize, stream: &mut Stream) -> Result<usize, &str> {
    let abc = ((stream.buff[pkt_offset] >> 3) & 0x04) | (stream.buff[pkt_offset] & 0x3);

    match abc {
        5 => {
            tracer_atom(&mut stream.tracer, AtomTypeN);
            tracer_atom(&mut stream.tracer, AtomTypeE);
            tracer_atom(&mut stream.tracer, AtomTypeE);
            tracer_atom(&mut stream.tracer, AtomTypeE);
            tracer_atom(&mut stream.tracer, AtomTypeE);
        }
        1 => {
            tracer_atom(&mut stream.tracer, AtomTypeN);
            tracer_atom(&mut stream.tracer, AtomTypeN);
            tracer_atom(&mut stream.tracer, AtomTypeN);
            tracer_atom(&mut stream.tracer, AtomTypeN);
            tracer_atom(&mut stream.tracer, AtomTypeN);
        }
        2 => {
            tracer_atom(&mut stream.tracer, AtomTypeN);
            tracer_atom(&mut stream.tracer, AtomTypeE);
            tracer_atom(&mut stream.tracer, AtomTypeN);
            tracer_atom(&mut stream.tracer, AtomTypeE);
            tracer_atom(&mut stream.tracer, AtomTypeN);
        }
        3 => {
            tracer_atom(&mut stream.tracer, AtomTypeE);
            tracer_atom(&mut stream.tracer, AtomTypeN);
            tracer_atom(&mut stream.tracer, AtomTypeE);
            tracer_atom(&mut stream.tracer, AtomTypeN);
            tracer_atom(&mut stream.tracer, AtomTypeE);
        }
        _ => {}
    }

    return Ok(1);
}

pub fn decode_atom_format_6(_: usize, _: &mut Stream) -> Result<usize, &str> {
    unimplemented!()
}

pub fn decode_q(_: usize, _: &mut Stream) -> Result<usize, &str> {
    unimplemented!()
}

pub const TRACEPKTS: [TracePkt; 56] = [
    TracePkt::new("extension", 0xff, 0x00),
    TracePkt::new("trace_info", 0xff, 0x01),
    TracePkt::new("trace_on", 0xff, 0x04),
    TracePkt::new("timestamp", 0xfe, 0x02),
    TracePkt::new("exception", 0xfe, 0x06),
    TracePkt::new("cc_format_1", 0xfe, 0x0e),
    TracePkt::new("cc_format_2", 0xfe, 0x0c),
    TracePkt::new("cc_format_3", 0xf0, 0x10),
    TracePkt::new("data_sync_marker", 0xf0, 0x20),
    TracePkt::new("commit", 0xff, 0x2d),
    TracePkt::new("cancel_format_1", 0xfe, 0x2e),
    TracePkt::new("cancel_format_2", 0xfc, 0x34),
    TracePkt::new("cancel_format_3", 0xf8, 0x38),
    TracePkt::new("mispredict", 0xfc, 0x30),
    TracePkt::new("cond_inst_format_1", 0xff, 0x6c),
    TracePkt::new("cond_inst_format_2", 0xfc, 0x40),
    TracePkt::new("cond_inst_format_3", 0xff, 0x6d),
    TracePkt::new("cond_flush", 0xff, 0x43),
    TracePkt::new("cond_result_format_1", 0xf8, 0x68),
    TracePkt::new("cond_result_format_2", 0xf8, 0x48),
    TracePkt::new("cond_result_format_3", 0xf0, 0x50),
    TracePkt::new("cond_result_format_4", 0xfc, 0x44),
    TracePkt::new("event", 0xf0, 0x70),
    TracePkt::new("short_address_is0", 0xff, 0x95),
    TracePkt::new("short_address_is1", 0xff, 0x96),
    TracePkt::new("long_address_32bit_is0", 0xff, 0x9a),
    TracePkt::new("long_address_32bit_is1", 0xff, 0x9b),
    TracePkt::new("long_address_64bit_is0", 0xff, 0x9d),
    TracePkt::new("long_address_64bit_is1", 0xff, 0x9e),
    TracePkt::new("exact_match_address", 0xfc, 0x90),
    TracePkt::new("context", 0xfe, 0x80),
    TracePkt::new("address_context_32bit_is0", 0xff, 0x82),
    TracePkt::new("address_context_32bit_is1", 0xff, 0x83),
    TracePkt::new("address_context_64bit_is0", 0xff, 0x85),
    TracePkt::new("address_context_64bit_is1", 0xff, 0x86),
    TracePkt::new("atom_format_1", 0xfe, 0xf6),
    TracePkt::new("atom_format_2", 0xfc, 0xd8),
    TracePkt::new("atom_format_3", 0xf8, 0xf8),
    TracePkt::new("atom_format_4", 0xfc, 0xdc),
    TracePkt::new("atom_format_5_1", 0xff, 0xf5),
    TracePkt::new("atom_format_5_2", 0xff, 0xd5),
    TracePkt::new("atom_format_5_3", 0xff, 0xd6),
    TracePkt::new("atom_format_5_4", 0xff, 0xd7),
    TracePkt::new("atom_format_6_1", 0xff, 0xd0),
    TracePkt::new("atom_format_6_2", 0xff, 0xd1),
    TracePkt::new("atom_format_6_3", 0xff, 0xd2),
    TracePkt::new("atom_format_6_4", 0xff, 0xd3),
    TracePkt::new("atom_format_6_5", 0xff, 0xd4),
    TracePkt::new("atom_format_6_6", 0xff, 0xf0),
    TracePkt::new("atom_format_6_7", 0xff, 0xf1),
    TracePkt::new("atom_format_6_8", 0xff, 0xf2),
    TracePkt::new("atom_format_6_9", 0xff, 0xf3),
    TracePkt::new("atom_format_6_10", 0xff, 0xf4),
    TracePkt::new("atom_format_6_11", 0xf0, 0xc0),
    TracePkt::new("atom_format_6_12", 0xf0, 0xe0),
    TracePkt::new("q", 0xf0, 0xa0),
];

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
                    Ok(_) => {
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
