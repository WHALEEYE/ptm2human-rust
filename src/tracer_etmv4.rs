use std::ops::Add;

#[derive(Default, Clone, Copy)]
pub struct AddressRegister {
    address: u64,
    IS: i32,
}

pub struct Etmv4Tracer {
    /* exactly the INFO field value in the TraceInfo packet */
    info: u32,

    /* Conditional tracing field. The Permitted values are:
      CONDTYPE_PASS_FAIL - Indicate if a conditional instruction passes or fails its check
      CONDTYPE_APSR      - Provide the value of the APSR condition flags
    */
    condtype: i32,
    commopt: i32,

    /* Trace analyzer state between receiving packets */
    timestamp: u64,
    address_register: [AddressRegister; 3],
    context_id: u32,
    // to be discussed: the following 4 fields uses bit field in C version
    vmid: u8,
    ex_level: u8,
    security: u8,
    sixty_four_bit: u8,

    curr_spec_depth: u32,
    p0_key: u32,
    cond_c_key: u32,
    cond_r_key: u32,
    p0_key_max: u32,
    cond_key_max_incr: u32,
    max_spec_depth: u32,
    cc_threshold: u32,
}

impl Etmv4Tracer {
    pub fn new() -> Self {
        Self {
            info: 0,
            condtype: 0,
            commopt: 0,
            timestamp: 0,
            address_register: [AddressRegister::default(); 3],
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
