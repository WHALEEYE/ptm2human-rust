use crate::tracer_etmv4::AddrReg::*;
use crate::tracer_etmv4::AtomType::*;

const EXP_NAME: [Option<&str>; 16] = [
    Some("PE reset"),
    Some("Debug halt"),
    Some("Call"),
    Some("Trap"),
    Some("System error"),
    None,
    Some("Inst debug"),
    Some("Data debug"),
    None,
    None,
    Some("Alignment"),
    Some("Inst fault"),
    Some("Data fault"),
    None,
    Some("IRQ"),
    Some("FIQ"),
];

#[derive(Clone, Copy, PartialEq, PartialOrd)]
pub enum AddrReg {
    AddrRegIsUnknown,
    AddrRegIs0,
    AddrRegIs1,
}

pub enum AtomType {
    AtomTypeE,
    AtomTypeN,
}

#[derive(Clone, Copy)]
pub struct AddressRegister {
    pub address: u64,
    pub is: AddrReg,
}

impl AddressRegister {
    pub fn new() -> Self {
        Self {
            address: 0,
            is: AddrRegIsUnknown,
        }
    }
}

pub struct Etmv4Tracer {
    /* exactly the INFO field value in the TraceInfo packet */
    pub info: u32,

    /* Conditional tracing field. The Permitted values are:
      CONDTYPE_PASS_FAIL - Indicate if a conditional instruction passes or fails its check
      CONDTYPE_APSR      - Provide the value of the APSR condition flags
    */
    pub condtype: i32,
    pub commopt: i32,
    /* Trace analyzer state between receiving packets */
    pub timestamp: u64,
    pub address_register: [AddressRegister; 3],
    pub context_id: u32,
    // to be discussed: the following 4 fields uses bit field in C version
    pub vmid: u8,
    pub ex_level: u8,
    pub security: bool,
    pub sixty_four_bit: bool,
    pub curr_spec_depth: u32,
    pub p0_key: u32,
    pub cond_c_key: u32,
    pub cond_r_key: u32,
    pub p0_key_max: u32,
    pub cond_key_max_incr: u32,
    pub max_spec_depth: u32,
    pub cc_threshold: u32,
}

impl Etmv4Tracer {
    pub fn new() -> Self {
        Self {
            info: 0,
            condtype: 0,
            commopt: 0,
            timestamp: 0,
            address_register: [AddressRegister::new(); 3],
            context_id: 0,
            vmid: 0,
            ex_level: 0,
            security: false,
            sixty_four_bit: false,
            curr_spec_depth: 0,
            p0_key: 0,
            cond_c_key: 0,
            cond_r_key: 0,
            p0_key_max: 0,
            cond_key_max_incr: 0,
            max_spec_depth: 0,
            cc_threshold: 0,
        }
    }
}

pub fn reset_address_register(tracer: &mut Etmv4Tracer) {
    tracer.address_register[0].address = 0;
    tracer.address_register[0].is = AddrRegIsUnknown;
    tracer.address_register[1].address = 0;
    tracer.address_register[1].is = AddrRegIsUnknown;
    tracer.address_register[2].address = 0;
    tracer.address_register[2].is = AddrRegIsUnknown;
}

pub fn tracer_trace_info(
    tracer: &mut Etmv4Tracer,
    plctl: u32,
    info: u32,
    key: u32,
    spec: u32,
    cyct: u32,
) {
    reset_address_register(tracer);

    tracer.info = if (plctl & 1) != 0 { info } else { 0 };
    tracer.p0_key = if (plctl & 2) != 0 { key } else { 0 };
    tracer.curr_spec_depth = if (plctl & 4) != 0 { spec } else { 0 };
    tracer.cc_threshold = if (plctl & 8) != 0 { cyct } else { 0 };

    println!(
        "TraceInfo - {},",
        if (tracer.info & 0x01) != 0 {
            "Cycle count enabled"
        } else {
            "Cycle count disabled"
        }
    );
    println!(
        "            {},",
        if (tracer.info & 0x0E) != 0 {
            "Tracing of conditional non-branch instruction enabled"
        } else {
            "Tracing of conditional non-branch instruction disabled"
        }
    );
    println!(
        "            {},",
        if (tracer.info & 0x10) != 0 {
            "Explicit tracing of load instructions"
        } else {
            "No explicit tracing of load instructions"
        }
    );
    println!(
        "            {},",
        if (tracer.info & 0x20) != 0 {
            "Explicit tracing of store instructions"
        } else {
            "No explicit tracing of store instructions"
        }
    );
    println!("            p0_key = 0x{:X},", tracer.p0_key);
    println!("            curr_spec_depth = {},", tracer.curr_spec_depth);
    println!("            cc_threshold = 0x{:X}", tracer.cc_threshold);
}

pub fn tracer_trace_on(_: &Etmv4Tracer) {
    println!("TraceOn - A discontinuity in the trace stream");
}

pub fn tracer_discard(_: &Etmv4Tracer) {
    unimplemented!()
}

pub fn tracer_overflow(_: &Etmv4Tracer) {
    unimplemented!()
}

pub fn tracer_ts(
    tracer: &mut Etmv4Tracer,
    timestamp: u64,
    have_cc: bool,
    count: u32,
    nr_replace: i32,
) {
    if timestamp != 0 {
        let (value, overflow) = (1 as i64).overflowing_shl(nr_replace as u32);
        let shifted_value = if overflow { 0 } else { value };
        tracer.timestamp &= !(shifted_value - 1) as u64;

        tracer.timestamp |= timestamp;
    }

    println!("Timestamp - {}", tracer.timestamp);
    if have_cc {
        println!(
            "            (number of cycles between the most recent Cycle Count element {})",
            count
        );
    }
}

pub fn tracer_exception(tracer: &mut Etmv4Tracer, tp: usize) {
    println!(
        "Exception - exception type {}, address 0x{:016x}",
        if tp < 32 && EXP_NAME[tp] != None {
            EXP_NAME[tp].unwrap()
        } else {
            "Reserved"
        },
        tracer.address_register[0].address
    );

    tracer_cond_flush(tracer);

    /*
     * If p0_key_max is zero, it implies that the target CPU uses no P0 right-hand keys.
     * If so, there is no need to update p0_key.
     */
    if tracer.p0_key_max != 0 {
        tracer.p0_key += 1;
        tracer.p0_key %= tracer.p0_key_max;
    }

    tracer.curr_spec_depth += 1;
    if tracer.max_spec_depth == 0 || (tracer.curr_spec_depth > tracer.max_spec_depth) {
        tracer_commit(tracer, 1);
    }
}

pub fn tracer_exception_return(_: &Etmv4Tracer) {
    println!("Exception return");
    /* FIXME: for ARMv6-M and ARMv7-M PEs, exception_return is a P0 element */
}

fn tracer_commit(tracer: &mut Etmv4Tracer, commit: u32) {
    println!("Commit - {}", commit);
    tracer.curr_spec_depth -= commit;
}

fn tracer_cond_flush(_: &Etmv4Tracer) {
    println!("Conditional flush");
}

pub fn tracer_address(tracer: &Etmv4Tracer) {
    let address = tracer.address_register[0].address;
    let is = tracer.address_register[0].is;

    if tracer.sixty_four_bit {
        println!(
            "Address - Instruction address 0x{:016x}, Instruction set Aarch64",
            address,
        );
    } else {
        if is != AddrRegIs0 {
            println!(
                "Address - Instruction address 0x{:016x}, Instruction set Aarch32 (ARM)",
                address,
            );
        } else {
            println!(
                "Address - Instruction address 0x{:016x}, Instruction set Aarch32 (Thumb)\n",
                address,
            );
        }
    }
}

pub fn tracer_context(
    tracer: &mut Etmv4Tracer,
    p: u8,
    el: u8,
    sf: u8,
    ns: u8,
    v: u8,
    vmid: u8,
    c: i32,
    contextid: u32,
) {
    if p != 0 {
        tracer.ex_level = el;
        tracer.sixty_four_bit = sf != 0;
        tracer.security = ns == 0;
        if v != 0 {
            tracer.vmid = vmid;
        }
        if c != 0 {
            tracer.context_id = contextid;
        }
    }

    println!("Context - Context ID = 0x{:X},", tracer.context_id);
    println!("          VMID = 0x{:X},", tracer.vmid);
    println!("          Exception level = EL{},", tracer.ex_level);
    println!(
        "          Security = {},",
        if tracer.security { "S" } else { "NS" }
    );
    println!(
        "          {}-bit instruction",
        if tracer.sixty_four_bit { 64 } else { 32 }
    );
}

pub fn tracer_atom(tracer: &mut Etmv4Tracer, tp: AtomType) {
    match tp {
        AtomTypeE => {
            println!("ATOM - E");
        }
        AtomTypeN => {
            println!("ATOM - N");
        }
    }

    /*
     * If p0_key_max is zero, it implies that the target CPU uses no P0 right-hand keys.
     * If so, there is no need to update p0_key.
     */
    if (tracer.p0_key_max) != 0 {
        tracer.p0_key += 1;
        tracer.p0_key %= tracer.p0_key_max;
    }

    tracer.curr_spec_depth += 1;
    if tracer.max_spec_depth == 0 || (tracer.curr_spec_depth > tracer.max_spec_depth) {
        tracer_commit(tracer, 1);
    }
}
