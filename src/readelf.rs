extern crate exefmt;
extern crate getopts;

use exefmt::elf;

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
}

enum ParseResult {
	Ok(ReadElfOptions, Vec<String>),
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
		parsed_opts.syms = true;

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

	if !parsed_opts.at_least_one_opt {
		return ParseResult::ErrUsage;
	}

	let files = if !matches.free.is_empty() {
		matches.free.clone()
	} else {
		return ParseResult::Err("No input files specified".to_string());
	};

	ParseResult::Ok(parsed_opts, files)
}

fn print_file_header(elf: &elf::ElfFile) {
	println!("ELF Header:");
	print!("  Magic:   ");
	for byte in elf.e_ident.iter() {
		print!("{:02x} ", byte);
	}
	println!("");
	println!("  Class:                             {}", elf.ehdr_class_string());
	println!("  Data:                              {}", elf.ehdr_data_string());
	let ident_ver = elf.e_ident[elf::EI_VERSION];
	println!("  Version:                           {}{}", ident_ver,
		if ident_ver == elf::EV_CURRENT { " (current)" }
		else { "" }
		);
	println!("  OS/ABI:                            {}", elf.ehdr_osabi_string());
	println!("  ABI Version:                       {}", elf.e_ident[elf::EI_ABIVERSION]);
	println!("  Type:                              {}", elf.ehdr_type_string());
	println!("  Machine:                           {}", elf.ehdr_machine_string());
	println!("  Version:                           {:#x}", elf.e_version);
	println!("  Entry point address:               {:#x}", elf.e_entry);
	println!("  Start of program headers:          {} (bytes into file)", elf.e_phoff);
	println!("  Start of section headers:          {} (bytes into file)", elf.e_shoff);
	print!("  Flags:                             {:#x}", elf.e_flags);
	for flag in elf.ehdr_flags_strings() {
		print!(", {}", flag);
	}
	println!("");
	println!("  Size of this header:               {} (bytes)", elf.e_ehsize);
	println!("  Size of program headers:           {} (bytes)", elf.e_phentsize);
	println!("  Number of program headers:         {}", elf.e_phnum);
	println!("  Size of section headers:           {} (bytes)", elf.e_shentsize);
	println!("  Number of section headers:         {}", elf.e_shnum);
	println!("  Section header string table index: {}", elf.e_shstrndx);
}

fn build_flags_str(flags: u64) -> String {
	let mut flags_str = "".to_string();

	if (flags & 0x00000001) != 0 {
		flags_str = flags_str + "W";
	}

	if (flags & 0x00000002) != 0 {
		flags_str = flags_str + "A";
	}

	if (flags & 0x00000004) != 0 {
		flags_str = flags_str + "X";
	}

	if (flags & 0x00000010) != 0 {
		flags_str = flags_str + "M";
	}

	if (flags & 0x00000020) != 0 {
		flags_str = flags_str + "S";
	}

	flags_str
}

fn print_section_headers(elf: &elf::ElfFile, parsed_opts: &ReadElfOptions) {
	if elf.e_shnum == 0 {
		println!("");
		println!("There are no sections in this file.\n");
		return;
	}

	if !parsed_opts.file_header {
		println!("There are {} section headers, starting at offset {:#x}:", elf.e_shnum, elf.e_shoff);
	}

	println!("");
	if elf.e_shnum > 1 {
		println!("Section Headers:");
	} else {
		println!("Section Header:");
	}

	match elf.e_ident[exefmt::elf::EI_CLASS] {
		exefmt::elf::ELFCLASS32 => {
			println!("  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al");
		},

		exefmt::elf::ELFCLASS64 => {
			println!("  [Nr] Name              Type             Address           Offset");
			println!("       Size              EntSize          Flags  Link  Info  Align");
		},

		_ => {
			
		},
	}

	let mut shnum = 0;
	for shdr in elf.shdrs.iter() {
		let section_name = match elf.strtab.read_str(shdr.sh_name) {
			Some(x) => x,
			None    => format!(""),
		};

		match elf.e_ident[exefmt::elf::EI_CLASS] {
			exefmt::elf::ELFCLASS32 => {
				println!("  [{:2}] {:<17.17} {:15} {:08x} {:06x} {:06x} {:02x} {:>3} {:2} {:3} {:2}", 
				         shnum, section_name, shdr.type_string(),
				         shdr.sh_addr, shdr.sh_offset, shdr.sh_size, shdr.sh_entsize,
				         build_flags_str(shdr.sh_flags), shdr.sh_link, shdr.sh_info,
				         shdr.sh_addralign);
			},

			exefmt::elf::ELFCLASS64 => {
				println!("  [{:2}] {:<17.17} {:16} {:016x}  {:08x}",
				         shnum, section_name, shdr.type_string(),
				         shdr.sh_addr, shdr.sh_offset);
				println!("       {:016x}  {:016x} {:>3}    {:4}   {:3}     {}",
				         shdr.sh_size, shdr.sh_entsize, build_flags_str(shdr.sh_flags), 
				         shdr.sh_link, shdr.sh_info, shdr.sh_addralign);
			},

			_ => {
				
			},
		}

		shnum += 1;
	}

	println!("Key to Flags:");
	if elf.e_machine == exefmt::elf::EM_AMD64 {
		println!("  W (write), A (alloc), X (execute), M (merge), S (strings), l (large)");
	} else {
		println!("  W (write), A (alloc), X (execute), M (merge), S (strings)");
	}
	println!("  I (info), L (link order), G (group), T (TLS), E (exclude), x (unknown)");
	println!("  O (extra OS processing required) o (OS specific), p (processor specific)");

}

fn sym_size_str(size: u64) -> String {
	match size {
		0 ... 99999 => format!("{}", size),
		_           => format!("{:#x}", size),
	}
}

fn print_symbols(elf: &elf::ElfFile, file: &mut std::fs::File) -> Result<(), exefmt::elf::ElfParseError> {
	let symtabs = try!(elf.read_symbols(file));
	let mut cur_sym_num: u32 = 0;

	for (symtab_name, symtab_shnum, symtab) in symtabs {
		let shdr = match elf.shdrs.get(symtab_shnum as usize) {
			Some(x) => x,
			None    => {
				return Err(exefmt::elf::ElfParseError::InvalidIdent);
			},
		}.clone();

		let strtab_shnum = match shdr.sh_link {
			0 ... 0xFFFF => shdr.sh_link as u16,
			_            => return Err(exefmt::elf::ElfParseError::InvalidIdent),
		};

		let strtab = try!(elf.read_section_as_strtab(strtab_shnum, file));

		println!("");
		println!("Symbol table '{}' contains {} entries:", symtab_name, symtab.len());

		match elf.e_ident[exefmt::elf::EI_CLASS] {
			exefmt::elf::ELFCLASS32 => {
				println!("   Num:    Value  Size Type    Bind   Vis      Ndx Name");
			},

			exefmt::elf::ELFCLASS64 => {
				println!("   Num:    Value          Size Type    Bind   Vis      Ndx Name");
			},

			_ => {
			},
		}

		for sym in symtab.iter() {
			let mut symbol_name = match strtab.read_str(sym.st_name) {
				Some(name) => name,
				None       => format!(""),
			};

			if symbol_name.len() > 25 {
				symbol_name.truncate(25);
			}
			match elf.e_ident[exefmt::elf::EI_CLASS] {
				exefmt::elf::ELFCLASS32 => {
					println!("{:6}: {:08x} {:>5} {:7} {:6} {:8} {:>3} {}", cur_sym_num, 
					         sym.st_value, sym_size_str(sym.st_size),
					         sym.type_string(elf.e_machine), sym.bind_string(),
					         sym.visibility_string(), sym.shndx_string(),
					         symbol_name);
				},

				exefmt::elf::ELFCLASS64 => {
					println!("{:6}: {:016x} {:>5} {:7} {:6} {:8} {:>3} {}", cur_sym_num,
					         sym.st_value, sym_size_str(sym.st_size),
					         sym.type_string(elf.e_machine), sym.bind_string(),
					         sym.visibility_string(), sym.shndx_string(),
					         symbol_name);
				},

				_ => {
				},
			}
			cur_sym_num += 1;
		}
	}

	Ok(())
}

fn read_file(file_name: String, parsed_opts: &ReadElfOptions) -> Result<(), String> {
	let mut file = match std::fs::File::open(file_name) {
		Ok(f) => f,
		Err(e) => return Err(format!("{}", e)),
	};


	let elf = match elf::ElfFile::read(&mut file) {
		Ok(elf) => elf,
		Err(_) => return Err("ReadError".to_string()),
	};

	if parsed_opts.file_header {
		print_file_header(&elf);
	}

	if parsed_opts.section_headers {
		print_section_headers(&elf, parsed_opts);
	}

	if parsed_opts.syms {
		match print_symbols(&elf, &mut file) {
			Ok(_) => { },
			Err(_) => return Err(format!("ElfParseError")),
		}
	}

	Ok(())
}

fn main() {
	let args: Vec<String> = std::env::args().collect();
	let program = args[0].clone();

	let mut opts = getopts::Options::new();

	match parse_opts(&args, &mut opts) {
		ParseResult::Ok(parsed_opts, files) => {
			let num_files = files.len();
			for file_name in files {
				if num_files != 1 {
					println!("");
					println!("File: {}", file_name);
				}

				match read_file(file_name, &parsed_opts) {
					Ok(_) => {},
					Err(e) => {
						println!("Error:  {}", e);
						std::process::exit(1);
					},
				}
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

