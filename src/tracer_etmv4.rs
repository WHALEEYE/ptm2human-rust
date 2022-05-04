use crate::tracer_etmv4::AddrReg::AddrRegIsUnknown;

#[derive(Clone, Copy)]
pub enum AddrReg {
    AddrRegIsUnknown,
    AddrRegIs0,
    AddrRegIs1,
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
    pub security: u8,
    pub sixty_four_bit: u8,
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
            security: 0,
            sixty_four_bit: 0,
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

pub fn tracer_trace_info(tracer: &mut Etmv4Tracer, plctl: u32, info: u32, key: u32, spec: u32, cyct: u32)
{
    reset_address_register(tracer);

    tracer.info = if (plctl & 1) != 0 { info } else { 0 };
    tracer.p0_key = if (plctl & 2) != 0 { key } else { 0 };
    tracer.curr_spec_depth = if (plctl & 4) != 0 { spec } else { 0 };
    tracer.cc_threshold = if (plctl & 8) != 0 { cyct } else { 0 };

    println!("TraceInfo - {},", if (tracer.info & 0x01) != 0 { "Cycle count enabled" } else { "Cycle count disabled" });
    println!("            {},", if (tracer.info & 0x0E) != 0 { "Tracing of conditional non-branch instruction enabled" } else { "Tracing of conditional non-branch instruction disabled" });
    println!("            {},", if (tracer.info & 0x10) != 0 { "Explicit tracing of load instructions" } else { "No explicit tracing of load instructions" });
    println!("            {},", if (tracer.info & 0x20) != 0 { "Explicit tracing of store instructions" } else { "No explicit tracing of store instructions" });
    println!("            p0_key = 0x{:X},", tracer.p0_key);
    println!("            curr_spec_depth = {},",tracer.curr_spec_depth);
    println!("            cc_threshold = 0x{:X}", tracer.cc_threshold);
}

pub fn tracer_trace_on(tracer: &Etmv4Tracer) {
    println!("TraceOn - A discontinuity in the trace stream");
}

pub fn tracer_discard(tracer: &Etmv4Tracer) {
    // Not Used
}

pub fn tracer_overflow(tracer: &Etmv4Tracer) {
    // Not Used
}
