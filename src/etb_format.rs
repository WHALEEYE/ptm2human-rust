use crate::stream;
use crate::stream::Stream;

const ETB_PACKET_SIZE: usize = 16;
const NULL_TRACE_SOURCE: u8 = 0x00;

pub fn decode_etb_stream(etb_stream: Stream) {
    let mut id: u8;
    let fsync = [0xff, 0xff, 0xff, 0x7f];

    /* create the first stream */
    let mut cur_id: Option<usize> = None;
    let mut pre_id: Option<usize> = None;
    let mut nr_stream = 1;
    let mut stream: Vec<Stream> = Vec::new();
    stream.push(etb_stream.init_new());

    let mut end: u8;
    let mut c: u8;
    let mut tmp: u8;

    let mut trace_stop = false;
    let mut pkt_idx = 0;
    loop {
        if trace_stop || pkt_idx >= etb_stream.buff.len() {
            break;
        }
        if etb_stream.buff[pkt_idx..(pkt_idx + 4)] == fsync {
            pkt_idx += fsync.len();
        }
        end = etb_stream.buff[pkt_idx + ETB_PACKET_SIZE - 1];

        for byte_idx in 0..(ETB_PACKET_SIZE - 1) {
            c = etb_stream.buff[pkt_idx + byte_idx];
            if (byte_idx & 1) != 0 {
                /* data byte */
                tmp = etb_stream.buff[pkt_idx + byte_idx - 1];
                if ((tmp & 1) != 0) && ((end & (1 << (byte_idx / 2))) != 0) {
                    if let Some(idx) = pre_id {
                        stream[idx].buff.push(c);
                    } else {
                        continue;
                    }
                } else {
                    /* data corresponds to the new ID */
                    if let Some(idx) = cur_id {
                        stream[idx].buff.push(c);
                    } else {
                        /* drop the byte since there is no ID byte yet */
                        continue;
                    }
                }
            } else {
                if (c & 1) != 0 {
                    /* ID byte */
                    id = (c >> 1) & 0x7f;
                    if id == NULL_TRACE_SOURCE {
                        trace_stop = true;
                        break;
                    } else {
                        pre_id = cur_id;
                        cur_id = Some((id - 1) as usize);
                    }
                    if let Some(idx) = cur_id {
                        if idx >= nr_stream {
                            /* create new streams */
                            let nr_new = idx - nr_stream + 1;
                            nr_stream = idx + 1;
                            for i in (nr_stream - nr_new)..nr_stream {
                                stream[i] = etb_stream.init_new();
                            }
                        }
                    }
                } else {
                    /* data byte */
                    c |= if (end & (1 << (byte_idx / 2))) != 0 {
                        1
                    } else {
                        0
                    };
                    if let Some(idx) = cur_id {
                        stream[idx].buff.push(c);
                    } else {
                        /* drop the byte since there is no ID byte yet */
                        continue;
                    }
                }
            }
        }
        pkt_idx += ETB_PACKET_SIZE;
    }

    for i in 0..nr_stream {
        if stream[i].buff.len() != 0 {
            println!("Decode trace stream of ID {}", i);
            stream::decode_stream(&mut stream[i]);
        } else {
            println!("There is no valid data in the stream of ID {}", i);
        }
    }
}
