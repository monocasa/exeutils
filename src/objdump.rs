#![feature(convert)]

extern crate exefmt;
extern crate getopts;
extern crate opcode;

use getopts::Options;

use std::io::{Error, ErrorKind};

use exefmt::Loader;

use opcode::chip8::Chip8Disasm;

use opcode::Arch;

#[derive(PartialEq)]
enum BinaryFormat {
	NotSet,

	RawBinary,
	Elf,
}

impl Default for BinaryFormat {
	fn default() -> BinaryFormat { BinaryFormat::NotSet }
}

#[derive(PartialEq)]
enum Disassemble {
	None,
	Executable,
	All,
}

impl Default for Disassemble {
	fn default() -> Disassemble { Disassemble::None }
}

#[derive(Default)]
struct ObjdumpOptions {
	bin_fmt: BinaryFormat,
	dis: Disassemble,
	arch: Option<opcode::Arch>,

	vma_offset: u64,

	at_least_one_opt: bool,
}

enum ParseError {
	Help,
	Ver,
	NoInputs,
	GetoptErr(getopts::Fail),
	PrintBinaryFormats,
	UnknownArgument(&'static str, String),
	MultipleSet(&'static str, String),
}

impl From<getopts::Fail> for ParseError {
	fn from(err: getopts::Fail) -> ParseError {
		ParseError::GetoptErr(err)
	}
}

type ParseResult = Result<(ObjdumpOptions, Vec<String>), ParseError>;

//const VERSION: &'static str = env!("CARGO_PKG_VERSION");

fn parse_hex(string: &String) -> Option<u64> {
	let mut base = 0;
	let mut value: u64 = 0;
	let v: Vec<char> = string.chars().collect();

	if (v.len() > 2) && (v[0] == '0') && (v[1] == 'x') {
		base = 2;
	}

	for character in v {
		if base > 0 {
			base -= 1;
			continue;
		}

		match character {
			'0' ... '9' => {
				value <<= 4;
				value += (character as u64) - ('0' as u64);
			},

			'a' ... 'f' => {
				value <<= 4;
				value += (character as u64) - ('a' as u64) + 0xa;
			},

			'A' ... 'F' => {
				value <<=4;
				value += (character as u64) - ('A' as u64) + 0xA;
			},

			_ => {
				return None;
			},
		}
	}

	Some(value)
}

fn print_help()
{
	println!("Help");
}

fn print_ver()
{
	println!("Ver");
}

fn print_bin_fmts()
{
	println!("Supported Targets:");
	println!("\tbinary - Raw binary");
	println!("\telf    - ELF file");
	println!("\t?      - Print this list");
}

fn print_usage(program_name: &str)
{
	println!("Usage: {} <option(s)> <file(s)>", program_name);
}

fn parse_target(targets: &Vec<String>, parsed_opts: &mut ObjdumpOptions) -> Result<(), ParseError> {
	for target in targets {
		let bin_fmt = match target.as_ref() {
			"binary" => { BinaryFormat::RawBinary },
			"elf"    => { BinaryFormat::Elf },
			"?"      => { return Err(ParseError::PrintBinaryFormats) },

			_ => { return Err(ParseError::UnknownArgument("target", target.clone())) },
		};

		if parsed_opts.bin_fmt == BinaryFormat::NotSet || parsed_opts.bin_fmt == bin_fmt {
			parsed_opts.bin_fmt = bin_fmt;
		} else {
			return Err(ParseError::MultipleSet("target", target.clone()));
		}
	}

	Ok(())
}

fn parse_opts(args: &Vec<String>, opts: &mut Options) -> ParseResult {
	let mut parsed_opts: ObjdumpOptions = Default::default();

	opts.optflag("H", "help",            "Display this information");
	opts.optflag("v", "version",         "Display the version number of readelf");
	opts.optflag("d", "disassemble",     "Disassemble executable sections");
	opts.optflag("D", "disassemble-all", "Disassemble all sections");

	opts.optflagopt("b", "target",     "Binary format.  Use \'?\' to list",           "FORMAT");
	opts.optflagopt("",  "adjust-vma", "Add OFFSET to all display section addresses", "OFFSET");
	opts.optflagopt("m", "machine",    "Machine architecture type",                   "MACHINE");

	let matches = try!(opts.parse(&args[1..]));

	if matches.opt_present("help") {
		return Err(ParseError::Help);
	}

	if matches.opt_present("version") {
		return Err(ParseError::Ver);
	}

	if matches.opt_present("disassemble") {
		parsed_opts.dis = Disassemble::Executable;

		parsed_opts.at_least_one_opt = true;
	}

	if matches.opt_present("disassemble-all") {
		parsed_opts.dis = Disassemble::All;

		parsed_opts.at_least_one_opt = true;
	}

	if matches.opt_present("machine") {
		parsed_opts.arch = match matches.opt_str("machine").unwrap().as_ref() {
			"chip8" => Some(opcode::Arch::Chip8),
			_ => return Err(ParseError::UnknownArgument("machine", matches.opt_str("machine").unwrap())),
		};
	}

	if matches.opt_present("target") {
		try!(parse_target(&matches.opt_strs("target"), &mut parsed_opts));
	}

	if matches.opt_present("adjust-vma") {
		parsed_opts.vma_offset = parse_hex(&matches.opt_str("adjust-vma").unwrap()).unwrap();
	}

	let files = if !matches.free.is_empty() {
		matches.free.clone()
	} else {
		return Err(ParseError::NoInputs);
	};

	Ok((parsed_opts, files))
}

fn on_err(err: ParseError, program_name: &str) {
	let ret_code = match err {
		ParseError::Help => {
			print_help();
			0
		},

		ParseError::PrintBinaryFormats => {
			print_bin_fmts();
			0
		},

		ParseError::NoInputs => {
			print_usage(program_name);
			1
		},

		ParseError::Ver => {
			print_ver();
			0
		},

		ParseError::GetoptErr(err) => {
			println!("ERROR: {}", err);
			print_usage(program_name);
			1
		},

		ParseError::UnknownArgument(key, value) => {
			println!("ERROR:  Unknown argument \"{}\" for key \"{}\"", value, key);
			print_usage(program_name);
			1
		},

		ParseError::MultipleSet(key, _) => {
			println!("ERROR:  Arg \"{}\" set multiple, mutually exclusive ways", key);
			print_usage(program_name);
			1
		},
	};

	std::process::exit(ret_code);
}

fn segment_filter_factory(parsed_options: &ObjdumpOptions) -> Box<Fn(&exefmt::Segment) -> bool> {
	match parsed_options.dis {
		Disassemble::None       => Box::new(|_| false),
		Disassemble::Executable => Box::new(|segment| segment.executable),
		Disassemble::All        => Box::new(|_| true),
	}
}

fn disassembler_factory(arch_type: &Option<opcode::Arch>) -> Box<opcode::Disassembler> {
	match arch_type {
		&Some(ref arch) => {
			match arch {
				&opcode::Arch::Chip8 => Box::new(opcode::chip8::Chip8Disasm),
				_ => panic!("Unknown machine"),
			}
		},
		&None => {
			panic!("Machine not set");
		},
	}
}

fn disassemble_segment(segment_meta: &exefmt::Segment, data: &Vec<u8>, parsed_options: &ObjdumpOptions) -> Result<(), std::io::Error> {
	let mut residue: usize = segment_meta.file_size as usize;
	let mut consumed: usize = 0;
	let base = segment_meta.load_base + parsed_options.vma_offset;
	let disassembler = disassembler_factory(&parsed_options.arch);

	println!("");
	println!("Disassembly of section {}", segment_meta.name);

	println!("");
	println!("{:08x} <{}>:", base, segment_meta.name);

	while residue != 0 {
		let (dis_text, num_bytes) = match disassembler.disassemble(base + (consumed as u64), &data.as_slice()[consumed .. data.len()]) {
			Ok((dis_text, num_bytes)) => (dis_text, num_bytes),
			Err(opcode::DisError::Unknown{ num_bytes }) => 
					(format!(".word 0x{:02x}{:02x}", data[consumed], data[consumed+1]), num_bytes),
			Err(opcode::DisError::MemOverflow) => {
				println!("{:8x}:    {:02x}       .byte 0x{:02x}", base + (consumed as u64), data[consumed], data[consumed]);
				consumed += 1;
				residue -= 1;
				continue;
			},
			Err(_) => {
				return Err(Error::new(ErrorKind::Other, "Diassembly error"));
			},
		};
		let byte_text = format!("{:02x} {:02x}", data[consumed], data[consumed+1]);
		println!("{:8x}:    {}    {}", base + (consumed as u64), byte_text, dis_text);
		consumed += num_bytes;
		residue -= num_bytes;
	}

	Ok(())
}

fn do_objdump(file_name: &String, parsed_options: &ObjdumpOptions) -> Result<(), std::io::Error> {
	let mut file = try!(std::fs::File::open(file_name));
	let filter = segment_filter_factory(parsed_options);

	let (segments, binfmt_name) = match parsed_options.bin_fmt {
		BinaryFormat::NotSet => {
			return Err(Error::new(ErrorKind::Other, "Unknown binary format"));
		},
		BinaryFormat::RawBinary => {
			let ldr = try!(exefmt::binary::BinLoader::new(&mut file));
			(try!(ldr.get_segments(&*filter, &mut file)), "binary".to_string())
		},
		BinaryFormat::Elf => {
			return Err(Error::new(ErrorKind::Other, "Have yet to implement ELF loading"));
		},
	};

	println!("");
	println!("{}:     file format {}", file_name, binfmt_name);
	println!("");

	for (segment_meta, data) in segments {
		match parsed_options.dis {
			Disassemble::None => {},
			Disassemble::Executable => { 
				if segment_meta.executable {
					try!(disassemble_segment(&segment_meta, &data, &parsed_options));
				}
			},
			Disassemble::All => {
				try!(disassemble_segment(&segment_meta, &data, &parsed_options));
			},
		}
	}

	Ok(())//parse_file(segments, parsed_options)
}

fn main() {
	let args: Vec<String> = std::env::args().collect();
	let program_name = args[0].clone();

	let mut opts = getopts::Options::new();

	match parse_opts(&args, &mut opts) {
		Ok((parsed_options, file_names)) => {
			for file_name in file_names {
				do_objdump(&file_name, &parsed_options).unwrap();
			}
		},
		Err(err) => {
			on_err(err, &program_name);
			println!("Error");
		},
	}
}

