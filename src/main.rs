use std::fs::File;
use std::io::Read;
use std::path::Path;

use clap::{arg, command};

mod stream;
mod tracer_etmv4;

fn main() {
    let mut output_path: Option<&Path> = None;
    let mut input_path: Option<&Path> = None;

    let matches = command!()
        .arg(arg!([input] "The file of the ETM stream").required(true))
        .arg(
            arg!(
                -o --output <FILE> "Redirect the decode results to another file"
            )
                .required(false)
                .allow_invalid_utf8(true),
        )
        .get_matches();

    if let Some(input) = matches.value_of("input") {
        input_path = Some(Path::new(input));
    }

    if let Some(output) = matches.value_of_os("output") {
        output_path = Some(Path::new(output));
    }

    let mut input_file = File::open(input_path.unwrap()).unwrap();
    let mut etm_stream = stream::Stream::new();
    input_file.read_to_end(&mut etm_stream.buff).unwrap();
}
