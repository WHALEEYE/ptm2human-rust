extern crate core;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use clap::{arg, command};

mod stream;
mod tracer_etmv4;
mod etb_format;
mod etmv4;
mod pktproto;

fn main() {
    let mut input_path: Option<&Path> = None;

    let matches = command!()
        .arg(arg!([input] "The file of the ETM stream").required(true))
        .arg(arg!(-o --output <FILE> "Redirect the decode results to another file")
                 .required(false)
                 .allow_invalid_utf8(true),
        ).get_matches();

    if let Some(input) = matches.value_of("input") {
        input_path = Some(Path::new(input));
    }

    let mut input_file = File::open(input_path.unwrap()).unwrap();
    let mut stream = stream::Stream::new();
    input_file.read_to_end(&mut stream.buff).unwrap();

    etb_format::decode_etb_stream(stream);
}
