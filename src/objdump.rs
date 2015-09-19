extern crate getopts;

use getopts::Options;

#[derive(PartialEq)]
enum BinaryFormat {
	NotSet,

	RawBinary,
	Elf,
}

impl Default for BinaryFormat {
	fn default() -> BinaryFormat { BinaryFormat::NotSet }
}

#[derive(Default)]
struct ObjdumpOptions {
	bin_fmt: BinaryFormat,
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

	opts.optflagopt("b", "target",     "Binary format.  Use \'?\' to list",           "FORMAT");
	opts.optflagopt("",  "adjust-vma", "Add OFFSET to all display section addresses", "OFFSET");

	opts.optflag("H", "help",     "Display this information");
	opts.optflag("v", "version",  "Display the version number of readelf");

	let matches = try!(opts.parse(&args[1..]));

	if matches.opt_present("help") {
		return Err(ParseError::Help);
	}

	if matches.opt_present("version") {
		return Err(ParseError::Ver);
	}

	if matches.opt_present("target") {
		try!(parse_target(&matches.opt_strs("target"), &mut parsed_opts));
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

fn main() {
	let args: Vec<String> = std::env::args().collect();
	let program_name = args[0].clone();

	let mut opts = getopts::Options::new();

	match parse_opts(&args, &mut opts) {
		Ok((_, _)) => {
			println!("objdump");
		},
		Err(err) => {
			on_err(err, &program_name);
			println!("Error");
		},
	}
}

