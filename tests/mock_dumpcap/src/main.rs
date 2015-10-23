//! A mockup of Wireshark's dumpcap for integration tests.

use std::env;
use std::io::Write;
use std::io;
use std::process;

#[derive(PartialEq)]
enum FailMode {
    Fast,     // Fail right away, no output at all
    Normal,   // Indicate some error condition and exit
    Illegal,  // Output some malformatted data for dumpcap to handle
    BadFilter // Capture filter failed to compile
}

const BAD_FILTER_MSG: u8 = 66;
const DROP_COUNT_MSG: u8 = 68;
const ERROR_MSG: u8 = 69;
const FILE_MSG: u8 = 70;
const PACKET_COUNT_MSG: u8 = 80;
const SUCCESS_MSG: u8 = 83;

enum Command {
    Capture,
    Version,
    Interfaces,
    Capabilities,
    Statistics
}

fn generate_msg<W, T>(buf: &mut W, msg_type: u8, msg: T) -> io::Result<usize> where T: AsRef<[u8]>, W: io::Write {
    let msg_ref = msg.as_ref();
    let msg_size = msg_ref.len() + 1;
    try!(buf.write(&[msg_type, (msg_size >> 16) as u8, (msg_size >> 8) as u8, msg_size as u8]));
    try!(buf.write_all(msg_ref));
    buf.write(&[0])
}

fn generate_error_msg<W, T>(mut buf: &mut W, err_msg1: T, err_msg2: T) -> io::Result<usize> where T: AsRef<[u8]>, W: io::Write {
    let mut err_msg = Vec::new();
    try!(generate_msg(&mut err_msg, ERROR_MSG, err_msg1));
    try!(generate_msg(&mut err_msg, ERROR_MSG, err_msg2));
    generate_msg(&mut buf, ERROR_MSG, err_msg)
}

fn parse_arguments() -> (Command, Option<String>, Option<FailMode>) {
    let mut interface = None;
    let mut cmd = Command::Capture;
    let mut fail_mode = None;

    let mut arg_iter = env::args().skip(1);
    loop {
        match arg_iter.next() {
            Some(arg) => {
                match &*arg {
                    "-M" => {},
                    "-i" => { interface = Some(arg_iter.next().unwrap()); },
                    "-Z" => { arg_iter.next().unwrap(); },
                    "--DUMPCAP_MOCK_FAIL_FAST" => fail_mode = Some(FailMode::Fast),
                    "--DUMPCAP_MOCK_FAIL_NORMAL" => fail_mode = Some(FailMode::Normal),
                    "--DUMPCAP_MOCK_FAIL_ILLEGAL" => fail_mode = Some(FailMode::Illegal),
                    "--DUMPCAP_MOCK_FAIL_FILTER" => fail_mode = Some(FailMode::BadFilter),
                    d => { cmd = match d {
                            "-v" => Command::Version,
                            "-D" => Command::Interfaces,
                            "-L" => Command::Capabilities,
                            "-S" => Command::Statistics,
                            _ => { panic!("Unexpected argument"); }
                         }
                    }
                }
            },
            None => break
        }
    }
    (cmd, interface, fail_mode)
}

fn main() {
    let (cmd, interface, fail_mode) = parse_arguments();
    match cmd {
        Command::Version => { version_string(fail_mode); }
        Command::Interfaces => { interfaces(fail_mode); }
        Command::Capabilities => { capabilities(fail_mode, interface.unwrap()) }
        Command::Statistics => statistics(fail_mode),
        Command::Capture => capture(fail_mode)
    }
}

fn version_string(fail_mode: Option<FailMode>) {
    match fail_mode {
        None => {
            println!("Mocked dumpcap");
        },
        Some(FailMode::Fast) => {
            write!(&mut io::stderr(), "Mock failed as it should").unwrap();
            process::exit(1);
        }
        _ => unimplemented!()
    }
}

fn interfaces(fail_mode: Option<FailMode>) {
    match fail_mode {
        None => {
            println!(concat!("1. em1\t\t\t0\t\tnetwork\n",
                             "2. lo\t\tLoopback\t0\t127.0.0.1,::1\tloopback"));
        },
        Some(FailMode::Fast) => {
            write!(&mut io::stderr(), "Mock failed as it should").unwrap();
            process::exit(1);
        }
        Some(FailMode::Illegal) => {
            println!("This is some garbage...");
        },
        _ => unimplemented!()
    }
}

fn capabilities(fail_mode: Option<FailMode>, iface: String) {
    match fail_mode {
        None => {
            match &*iface {
                "em1" => {
                    generate_msg(&mut io::stderr(), SUCCESS_MSG, "This was a triumph").unwrap();
                    println!(concat!("1\n", "1\tEN10MB\tEthernet\n", "143\tDOCSIS\tDOCSIS\n"));
                },
                "lo" => {
                    generate_msg(&mut io::stderr(), SUCCESS_MSG, "This was a triumph").unwrap();
                    println!(concat!("0\n", "1\tEN10MB\tEthernet\n"));
                },
                _ => unimplemented!()
            }
        },
        Some(FailMode::Illegal) => {
            generate_msg(&mut io::stderr(), SUCCESS_MSG, "This is not the output you are looking for").unwrap();
            println!("1\nThis\tis\tgarbage");
        },
        Some(FailMode::Normal) => {
            generate_msg(&mut io::stderr(), SUCCESS_MSG, "Ok, but I won't talk to you...").unwrap();
            println!(concat!("0\n", "1\tFOO\tBAR\n"));
            process::exit(1);
        },
        Some(FailMode::Fast) => {
            process::exit(1);
        }
        _ => unimplemented!()
    }
}

fn statistics(fail_mode: Option<FailMode>) {
    match fail_mode {
        None => {
            generate_msg(&mut io::stderr(), SUCCESS_MSG, "Ok, here are some stats").unwrap();
            println!("foo1\t4711\t123");
            println!("bar2\t4811\t456");
        },
        Some(FailMode::Normal) => {
            generate_msg(&mut io::stderr(), SUCCESS_MSG, "Ok, here are some stats, but I'll fail soon").unwrap();
            println!("foo1\t4711\t123");
            process::exit(2);
        },
        Some(FailMode::Illegal) => {
            generate_msg(&mut io::stderr(), SUCCESS_MSG, "Ok, here is some garbage").unwrap();
            println!("this is some bad output on stdout!");
        },
        Some(FailMode::Fast) => {
            process::exit(1);
        }
        _ => unimplemented!()
    }
}

fn capture(fail_mode: Option<FailMode>) {
    let stderr = &mut io::stderr();
    match fail_mode {
        None => {
            generate_msg(stderr, FILE_MSG, "foo.filename").unwrap();
            generate_msg(stderr, PACKET_COUNT_MSG, "123").unwrap();
            generate_msg(stderr, DROP_COUNT_MSG, "456").unwrap();
        },
        Some(FailMode::Fast) => {
            process::exit(1);
        }
        Some(FailMode::Illegal) => {
            generate_msg(stderr, 0, "This is an illegal meessage").unwrap();
        },
        Some(FailMode::BadFilter) => {
            generate_msg(stderr, BAD_FILTER_MSG, "This is a cat with a watermelon. Your capture filter is invalid").unwrap();
            process::exit(2);
        },
        Some(FailMode::Normal) => {
            generate_msg(stderr, SUCCESS_MSG, "Nothing to see here, move along").unwrap();
            generate_error_msg(stderr, "Oh now you see it?", "This is an error!").unwrap();
            process::exit(2);
        }
    }
}
