extern crate getopts;

use getopts::Options;

#[derive(Default)]
struct ReadElfOptions {
	file_header:      bool,
	program_headers:  bool,
	section_headers:  bool,
	section_groups:   bool,
	section_details:  bool,
	syms:             bool,
	dyn_syms:         bool,
	notes:            bool,
	relocs:           bool,
	unwind:           bool,
	dynamic:          bool,
	version_info:     bool,
	arch_specific:    bool,
	archive_index:    bool,
	use_dynamic:      bool,
	histogram:        bool,

	at_least_one_opt: bool,

	files:            Vec<String>,
}

enum ParseResult {
	Ok(ReadElfOptions),
	Err(String),
	ErrUsage,
	Help,
	Ver,
}

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

fn print_usage(program: &str, opts: &Options) {
	let brief = format!("Usage: {} [options] elffile...", program);
	print!("{}", opts.usage(&brief));
}

fn print_version() {
	println!("exeutils readelf {}", VERSION);
	println!("Copyright 2015 Tristan Miller");
	println!("This program is free software; you may redistribute it under the terms of");
	println!("the GNU General Public License version 3 or (at your option) any later version.");
	println!("This program has absolutely no warranty.");
}

fn parse_opts(args: &Vec<String>, opts: &mut Options) -> ParseResult {
	let mut parsed_opts: ReadElfOptions = Default::default();

	opts.optflag("a", "all",             "Equivalent to: -h -l -S -s -r -d -V -A -I");
	opts.optflag("h", "file-header",     "Display the ELF file header");
	opts.optflag("l", "program-headers", "Display the program headers");
	opts.optflag("",  "segments",        "An alias for --program-headers");
	opts.optflag("S", "section-headers", "Display the sections' header");
	opts.optflag("",  "sections",        "An alias for --section-headers");
	opts.optflag("g", "section-groups",  "Display the section groups");
	opts.optflag("t", "section-details", "Display the section details");
	opts.optflag("e", "headers",         "Equivalent to: -h -l -S");
	opts.optflag("s", "syms",            "Display the symbol table");
	opts.optflag("",  "symbols",         "An alias for --syms");
	opts.optflag("",  "dyn-syms",        "Display the dynamic symbol table");
	opts.optflag("n", "notes",           "Display the core notes (if present)");
	opts.optflag("r", "relocs",          "Display the relocations (if present)");
	opts.optflag("u", "unwind",          "Display the unwind info (if present)");
	opts.optflag("d", "dynamic",         "Display the dynamic section (if present)");
	opts.optflag("V", "version-info",    "Display the version sections (if present)");
	opts.optflag("A", "arch-specific",   "Display architecture specific information (if any)");
	opts.optflag("c", "archive-index",   "Display the symbol/file index in an archive");
	opts.optflag("D", "use-dynamic",     "Use the dynamic section info when displaying symbols");
	opts.optflag("I", "histogram",       "Display histogram of bucket list lengths");
	opts.optflag("H", "help",            "Display this information");
	opts.optflag("v", "version",         "Display the version number of readelf");

	let matches = match opts.parse(&args[1..]) {
		Ok(m) => { m }
		Err(f) => {
			return ParseResult::Err(f.to_string());
		}
	};

	if matches.opt_present("help") {
		return ParseResult::Help;
	}

	if matches.opt_present("version") {
		return ParseResult::Ver;
	}

	if matches.opt_present("all") {
		parsed_opts.file_header = true;
		parsed_opts.program_headers = true;
		parsed_opts.section_headers = true;
		parsed_opts.syms = true;
		parsed_opts.relocs = true;
		parsed_opts.dynamic = true;
		parsed_opts.version_info = true;
		parsed_opts.arch_specific = true;
		parsed_opts.histogram = true;

		parsed_opts.at_least_one_opt = true;
	}

	if matches.opt_present("file-header") {
		parsed_opts.file_header = true;

		parsed_opts.at_least_one_opt = true;
	}

	if matches.opt_present("program-headers") || matches.opt_present("segments") {
		parsed_opts.program_headers = true;

		parsed_opts.at_least_one_opt = true;
	}

	if matches.opt_present("section-headers") || matches.opt_present("sections") {
		parsed_opts.section_headers = true;

		parsed_opts.at_least_one_opt = true;
	}

	if matches.opt_present("section-groups") {
		parsed_opts.section_groups = true;

		parsed_opts.at_least_one_opt = true;
	}

	if matches.opt_present("section-details") {
		parsed_opts.section_details = true;

		parsed_opts.at_least_one_opt = true;
	}

	if matches.opt_present("headers") {
		parsed_opts.file_header = true;
		parsed_opts.program_headers = true;
		parsed_opts.section_headers = true;

		parsed_opts.at_least_one_opt = true;
	}

	if matches.opt_present("syms") || matches.opt_present("symbols") {
		parsed_opts.section_headers = true;

		parsed_opts.at_least_one_opt = true;
	}

	if matches.opt_present("dyn-syms") {
		parsed_opts.dyn_syms = true;

		parsed_opts.at_least_one_opt = true;
	}

	if matches.opt_present("notes") {
		parsed_opts.notes = true;

		parsed_opts.at_least_one_opt = true;
	}

	if matches.opt_present("relocs") {
		parsed_opts.relocs = true;

		parsed_opts.at_least_one_opt = true;
	}

	if matches.opt_present("unwind") {
		parsed_opts.unwind = true;

		parsed_opts.at_least_one_opt = true;
	}

	if matches.opt_present("dynamic") {
		parsed_opts.dynamic = true;

		parsed_opts.at_least_one_opt = true;
	}

	if matches.opt_present("version-info") {
		parsed_opts.version_info = true;

		parsed_opts.at_least_one_opt = true;
	}

	if matches.opt_present("arch-specific") {
		parsed_opts.arch_specific = true;

		parsed_opts.at_least_one_opt = true;
	}

	if matches.opt_present("archive-index") {
		parsed_opts.archive_index = true;

		parsed_opts.at_least_one_opt = true;
	}

	if matches.opt_present("use-dynamic") {
		parsed_opts.use_dynamic = true;
	}

	if matches.opt_present("histogram") {
		parsed_opts.histogram = true;

		parsed_opts.at_least_one_opt = true;
	}

	parsed_opts.files = if !matches.free.is_empty() {
		matches.free.clone()
	} else {
		return ParseResult::Err("No input files specified".to_string());
	};

	if !parsed_opts.at_least_one_opt {
		return ParseResult::ErrUsage;
	}

	ParseResult::Ok(parsed_opts)
}

fn read_file(file_name: String) -> Result<(), String> {
	let file = match std::fs::File::open(file_name) {
		Ok(f) => f,
		Err(e) => return Err(format!("{}", e)),
	};

	println!("Opened:  {:?}", file);
	Err("Unimplemented".to_string())
}

fn main() {
	let args: Vec<String> = std::env::args().collect();
	let program = args[0].clone();

	let mut opts = getopts::Options::new();

	match parse_opts(&args, &mut opts) {
		ParseResult::Ok(parsed_opts) => {
			let num_files = parsed_opts.files.len();
			for file_name in parsed_opts.files {
				if num_files != 1 {
					println!("");
					println!("File: {}", file_name);
				}

				read_file(file_name).unwrap();
			}
		},
		ParseResult::Err(e) => {
			println!("Error:  {}", e);
			print_usage(&program, &opts);
			std::process::exit(1);
		},
		ParseResult::ErrUsage => {
			print_usage(&program, &opts);
			std::process::exit(1);
		},
		ParseResult::Help => {
			print_usage(&program, &opts);
			return;
		},
		ParseResult::Ver => {
			print_version();
			return;
		},
	}
}

