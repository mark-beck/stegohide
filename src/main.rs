#![feature(try_blocks)]

use clap::{clap_app, AppSettings::SubcommandRequired};
use itertools::Itertools;
use std::convert::TryInto;
use std::fs::File;
use std::io::BufWriter;
use std::ops::Shl;
use std::ops::{BitAnd, BitOr};
use std::path::Path;

fn main() {
    let matches = clap_app!(stegohide =>
        (version: "1.0")
        (author: "Mark B.")
        (about: "PNG Steganography")
        (setting: SubcommandRequired)
        (@subcommand encode =>
            (about: "decode message from png")
            (@arg file: +required "png file to use")
            (@arg message: +required "message to hide")
            (@arg output: -o --out +takes_value "output file")
        )
        (@subcommand decode =>
            (about: "encode message into png")
            (@arg file: +required "png file to use")
        )
        (@subcommand debugmessage =>
            (about: "print bytestream for message")
            (@arg message: +required "message to debug")
        )
        (@subcommand debugfile =>
            (about: "print bytestream of file")
            (@arg file: +required "file to debug")
        )
    )
    .get_matches();

    match matches.subcommand() {
        ("decode", Some(matches)) => decode(matches.value_of("file").unwrap()),
        ("encode", Some(matches)) => encode(
            matches.value_of("file").unwrap(),
            matches.value_of("message").unwrap(),
            matches
                .value_of("output")
                .or_else(|| matches.value_of("file"))
                .unwrap(),
        ),
        ("debugmessage", Some(matches)) => debugmessage(matches.value_of("message").unwrap()),
        ("debugfile", Some(matches)) => debugfile(matches.value_of("file").unwrap()),
        _ => unreachable!(),
    }
}

struct Image {
    bytes: Vec<u8>,
    alpha: Option<Vec<u8>>,
    info: png::OutputInfo,
}

fn decode(file: &str) {
    match File::open(file) {
        Ok(file) => {
            let image = get_bytes(&file);
            let extracted_bytes = extract_bytes(&image.bytes);
            if check_magic_bytes(&extracted_bytes) {
                let message = extracted_bytes
                    .iter()
                    .skip(8)
                    .take(get_length(&extracted_bytes))
                    .map(|e| *e as char)
                    .collect::<String>();
                println!("{message}");
            } else {
                eprintln!("no message");
            }
        }
        Err(_) => eprintln!("invalid file"),
    }
}

fn encode(file: &str, message: &str, output: &str) {
    match File::open(file) {
        Ok(file) => {
            let image = get_bytes(&file);
            println!("encoding message \"{message}\" into file {output}");
            let path = Path::new(output);
            let file = File::create(path).unwrap();
            let w = BufWriter::new(file);

            let mut encoder = png::Encoder::new(w, image.info.width, image.info.height);
            encoder.set_color(image.info.color_type);
            encoder.set_depth(png::BitDepth::Eight);
            let mut writer = encoder.write_header().unwrap();

            writer
                .write_image_data(&add_alpha(
                    inject_message(&image.bytes, message),
                    image.alpha,
                ))
                .unwrap();
        }
        Err(_) => eprintln!("invalid file"),
    }
}

fn check_magic_bytes(bytes: &[u8]) -> bool {
    bytes.iter().take(4).map(|e| *e as char).collect::<String>() == "BHTM"
}

fn get_length(bytes: &[u8]) -> usize {
    let int_bytes = &bytes[4..8];
    u32::from_be_bytes(int_bytes.try_into().unwrap()) as usize
}

fn extract_bytes(rgb_bytes: &[u8]) -> Vec<u8> {
    let mut extracted = Vec::with_capacity(rgb_bytes.len() / 4);
    for chunk in rgb_bytes.chunks(4) {
        let _: Option<()> = try {
            let mut chunk = chunk.iter();
            let v1 = (chunk.next()? & 0x3).shl(6);
            let v2 = (chunk.next()? & 0x3).shl(4);
            let v3 = (chunk.next()? & 0x3).shl(2);
            let v4 = (chunk.next()? & 0x3).shl(0);
            extracted.push(v1 | v2 | v3 | v4);
        };
    }
    extracted
}

fn get_bytes(file: &File) -> Image {
    let mut decoder = png::Decoder::new(file);
    decoder.set_transformations(png::Transformations::normalize_to_color8());
    let mut reader = decoder.read_info().unwrap();

    let buffersize = reader.output_buffer_size();

    let mut bytes = vec![0; buffersize];
    let info = reader.next_frame(&mut bytes).unwrap();

    let mut alpha = None;

    if info.color_type == png::ColorType::Rgba {
        alpha = Some(
            bytes
                .iter()
                .enumerate()
                .filter(|(i, _)| i % 4 == 3)
                .map(|(_, e)| *e)
                .collect(),
        );
        bytes = bytes
            .into_iter()
            .enumerate()
            .filter(|(i, _)| i % 4 != 3)
            .map(|(_, e)| e)
            .collect();
    }
    Image { bytes, alpha, info }
}

fn split_bytes(bytes: &[u8]) -> impl Iterator<Item = u8> + '_ {
    bytes.iter().flat_map(|e| {
        [
            e.rotate_right(6) & 0x3,
            e.rotate_right(4) & 0x3,
            e.rotate_right(2) & 0x3,
            e.rotate_right(0) & 0x3,
        ]
    })
}

fn add_alpha(bytes: Vec<u8>, alpha: Option<Vec<u8>>) -> Vec<u8> {
    match alpha {
        Some(alpha) => bytes
            .into_iter()
            .chunks(3)
            .into_iter()
            .interleave(alpha.into_iter().chunks(1).into_iter())
            .flatten()
            .collect(),
        None => bytes,
    }
}

fn inject_message(bytes: &[u8], message: &str) -> Vec<u8> {
    let lenght = (message.len() as u32).to_be_bytes().to_vec();
    let magic = b"BHTM".to_vec();

    let full_message = split_bytes(&magic)
        .chain(split_bytes(&lenght))
        .chain(split_bytes(message.as_bytes()))
        .map(Some)
        .chain(std::iter::repeat(None));

    bytes
        .iter()
        .zip(full_message)
        .map(|(byte, message)| message.map_or(*byte, |m| byte.bitand(0b1111_1100).bitor(m)))
        .collect()
}

fn debugmessage(message: &str) {
    let lenght = (message.len() as u32).to_be_bytes().to_vec();
    println!("message len: {}", message.len());
    let magic = b"BHTM".to_vec();

    println!(
        "{:?}",
        split_bytes(&magic)
            .chain(split_bytes(&lenght))
            .chain(split_bytes(message.as_bytes()))
            .collect::<Vec<u8>>()
    );

    println!(
        "{:2X?}",
        magic
            .iter()
            .chain(&lenght)
            .chain(message.as_bytes())
            .collect::<Vec<&u8>>()
    );
}

fn debugfile(file: &str) {
    match File::open(file) {
        Ok(file) => {
            let image = get_bytes(&file);
            for byte in image.bytes.iter().take(10) {
                println!("{:2x} ", byte);
            }
            for row in extract_bytes(&image.bytes).chunks(8) {
                for c in row {
                    print!("{:2x} ", c);
                }
                print!("  ");
                for c in row {
                    print!("{}", (*c as char).escape_default());
                }
                println!();
            }
        }
        Err(_) => eprintln!("invalid file"),
    }
}
