#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]

#![deny(missing_docs, trivial_casts, trivial_numeric_casts, unsafe_code,
        unused_import_braces, unused_qualifications)]
//! dumpcap provides an interface to Wireshark's dumpcap tool.
//! You can use dumpcap to
//!
//! * find out about available network interfaces and their supported
//!   capabilities.
//! * Receive live statistics about traffic seen on each interface.
//! * Capture traffic and save it to disk for further processing.

use std::error::Error;
use std::ffi;
use std::fmt;
use std::io::{Read, BufRead};
use std::io;
use std::sync::mpsc;
use std::num;
use std::process;
use std::result;
use std::string;
use std::thread;

extern crate regex;

const BAD_FILTER_MSG: u8 = 66;
const DROP_COUNT_MSG: u8 = 68;
const ERROR_MSG: u8 = 69;
const FILE_MSG: u8 = 70;
const PACKET_COUNT_MSG: u8 = 80;
const SUCCESS_MSG: u8 = 83;

/// Major types of errors this lib will expose
#[derive(Debug, PartialEq, Clone)]
pub enum ErrorKind {
    /// The dumpcap-subprocess has exited with a failure status or had no output
    DumpcapFailed,
    /// This library was unable to parse a status message sent by dumpcap. This is a bug.
    InvalidMessage,
    /// Internal errors (e.g. io::Error)
    Internal,
}

/// An opaque type recording error details
#[derive(Debug)]
pub struct DumpcapError {
    kind: ErrorKind,
    error: Box<Error + Send + Sync>,
}

impl DumpcapError {
    fn new<E>(kind: ErrorKind, error: E) -> Self
        where E: Into<Box<Error + Send + Sync>>
    {
        DumpcapError {
            kind: kind,
            error: error.into(),
        }
    }

    /// The major type of error
    pub fn kind(&self) -> ErrorKind {
        self.kind.clone()
    }
}

impl Error for DumpcapError {
    fn description(&self) -> &str {
        self.error.description()
    }

    fn cause(&self) -> Option<&Error> {
        self.error.cause()
    }
}

impl fmt::Display for DumpcapError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{:?} ({})", self.kind, self.error.description())
    }
}

impl From<io::Error> for DumpcapError {
    fn from(e: io::Error) -> Self {
        DumpcapError::new(ErrorKind::Internal, e)
    }
}

impl From<string::FromUtf8Error> for DumpcapError {
    fn from(e: string::FromUtf8Error) -> Self {
        DumpcapError::new(ErrorKind::Internal, e)
    }
}

impl From<num::ParseIntError> for DumpcapError {
    fn from(e: num::ParseIntError) -> Self {
        DumpcapError::new(ErrorKind::Internal, e)
    }
}

impl From<&'static str> for DumpcapError {
    fn from(e: &'static str) -> Self {
        DumpcapError::new(ErrorKind::Internal, e)
    }
}

const DEVICES_REGEX: &'static str = concat!("(?m:^)",
                                            r"(\d+)\. ", // the device number
                                            "([^\t]+)\t", // the device name
                                            "([^\t]*)\t", // the vendor name
                                            "([^\t]*)\t", // the human friendly name
                                            r"(\d+)\t", // the interface type
                                            r"([a-fA-F0-9\.:,]*)\t", // known addresses
                                            r"(\w+)", // "loopback" or "network"
                                            "(?m:\r?$)", // newline
                                            "");

/// A prefixed Result-type that indicates the error condition by DumpcapError
pub type Result<T> = result::Result<T, DumpcapError>;


/// Dumpcap allows calls to Wireshark's dumpcap-tool
#[derive(Debug)]
pub struct Dumpcap {
    /// The executable to use, possibly including the full path
    pub executable: ffi::OsString,
    /// Raw extra arguments to pass to dumpcap
    pub extra_args: Vec<String>,
}

impl Dumpcap {
    /// Create a new Dumpcap-struct with the executable set to "dumpcap"
    pub fn new() -> Dumpcap {
        Self::new_with_executable("dumpcap")
    }

    /// Create a new Dumpcap-struct with the given executable (possibly including the full path)
    pub fn new_with_executable<S>(executable: S) -> Dumpcap
        where S: Into<ffi::OsString>
    {
        Dumpcap {
            executable: executable.into(),
            extra_args: vec![],
        }
    }

    /// Return the first line "dumpcap -v" gives. The line usually takes the form "Dumpcap X.Y.Z
    /// (Git ...)"
    pub fn version_string(&self) -> Result<String> {
        let output = try!(process::Command::new(&self.executable)
                              .arg("-v")
                              .args(&self.extra_args)
                              .output());
        if !output.status.success() {
            return Err(DumpcapError::new(ErrorKind::DumpcapFailed,
                                         try!(String::from_utf8(output.stderr))));
        }
        match io::BufReader::new(io::Cursor::new(output.stdout)).lines().next() {
            Some(st) => Ok(try!(st)),
            None => Err(DumpcapError::new(ErrorKind::DumpcapFailed, "No output from dumpcap")),
        }
    }

    /// Call dumcap to receive live statistics about arriving traffic
    ///
    /// If the call to dumpcap succeeds, the given function is called about once per second
    /// and interface. That function should return as soon as possible to avoid blocking the thread
    /// reading from dumpcap.
    ///
    /// Returns:
    /// Handles to the dumpcap-subprocess and the thread listening to dumpcap's output and calling
    /// the given function. One should call .kill() on the Child to stop dumpcap and only then
    /// .join() on the JoinHandle to phase out processing dumpcap's output and check for errors.
    pub fn statistics<F>(&self, cb: F) -> Result<(process::Child, thread::JoinHandle<Result<()>>)>
        where F: Fn(DeviceStats) + Send + 'static
    {
        let mut args = Arguments::default();
        args.child_mode = true;
        args.command = Some("-S".to_owned());
        let mut child = try!(process::Command::new(&self.executable)
                                 .args(&args.build())
                                 .args(&self.extra_args)
                                 .stderr(process::Stdio::piped())
                                 .stdin(process::Stdio::null())
                                 .stdout(process::Stdio::piped())
                                 .spawn());
        try!(PipeReader(child.stderr.take().unwrap()).wait_for_success_msg());
        let stdout = child.stdout.take().unwrap();
        Ok((child,
            thread::spawn(move || {
            for line in io::BufReader::new(stdout).lines() {
                let l = &try!(line);
                cb(try!(parse_statistics(l)))
            }
            Ok(())
        })))
    }

    /// Call dumpcap to receive live statistics about arriving traffic
    ///
    /// Returns:
    /// An iterator that blocks when advancing until new statistics from dumpcap are available. The
    /// subprocess is terminated automatically when the iterator get's dropped.
    pub fn stats_iter(&self) -> DumpcapIterator<DeviceStats> {
        let (tx, rx) = mpsc::channel();
        let (child, handler) = self.statistics(move |s| tx.send(s).unwrap()).unwrap();
        DumpcapIterator {
            child: child,
            handler: Some(handler),
            rx: rx,
        }
    }

    /// Call dumpcap to capture network data according to the given arguments.
    ///
    /// If the call to dumpcap succeeds, the given function is called with messages sent by the
    /// dumpcap-subprocess.
    ///
    /// Returns:
    /// Handles to the dumpcap-subprocess and the thread passing messages from dumpcap to the given
    /// callback. One should call .kill() on the Child to stop dumpcap and only then .join() on the
    /// JoinHandle to phase out processing dumpcap's output and check for errors.
    pub fn capture<F>(&self,
                      mut args: Arguments,
                      cb: F)
                      -> Result<(process::Child, thread::JoinHandle<Result<()>>)>
        where F: Fn(Message) + Send + 'static
    {
        args.child_mode = true;
        let mut child = try!(process::Command::new(&self.executable)
                                 .args(&args.build())
                                 .args(&self.extra_args)
                                 .stderr(process::Stdio::piped())
                                 .stdin(process::Stdio::null())
                                 .stdout(process::Stdio::null())
                                 .spawn());
        let stderr = child.stderr.take().unwrap();
        Ok((child,
            thread::spawn(move || {
            for msg in PipeReader(stderr) {
                cb(try!(msg));
            }
            Ok(())
        })))

    }

    /// Call dumpcap to capture network data according to the given arguments.
    ///
    /// Returns:
    /// An iterator that blocks when advancing until new messages from dumpcap are available. The
    /// subprocess is terminated automatically when the iterator get's dropped.
    pub fn capture_iter(&self, args: Arguments) -> DumpcapIterator<Message> {
        let (tx, rx) = mpsc::channel();
        let (child, handler) = self.capture(args, move |msg| tx.send(msg).unwrap()).unwrap();
        DumpcapIterator {
            child: child,
            handler: Some(handler),
            rx: rx,
        }
    }

    /// Call dumpcap to receive a list of all devices possibly capable of capturing network
    /// traffic.
    ///
    /// If capabilities is true, a second call to dumpcap is made for each device to find out about
    /// supported link-layer types (monitor_mode is false during these calls).
    pub fn query_devices(&self, capabilities: bool) -> Result<Vec<Device>> {
        let output = try!(process::Command::new(&self.executable)
                              .arg("-M")
                              .arg("-D")
                              .args(&self.extra_args)
                              .output());
        if !output.status.success() {
            return Err(DumpcapError::new(ErrorKind::DumpcapFailed,
                                         try!(String::from_utf8(output.stderr))));
        }
        let stdout = try!(String::from_utf8(output.stdout));
        let mut v = Vec::new();
        for grp in regex::Regex::new(DEVICES_REGEX).unwrap().captures_iter(&stdout) {
            let dev_name = grp.at(2).unwrap();
            let caps = if capabilities {
                match self.query_capabilities(dev_name, false) {
                    Ok(c) => Some(c),
                    Err(..) => None,
                }} else { None };
            let dev = Device {
                dev_type: DeviceType::from(grp.at(5).unwrap()),
                name: dev_name.to_owned(),
                number: try!(grp.at(1).unwrap().parse()),
                vendor_name: grp.at(3).and_then(|s| {
                    match s {
                        "" => None,
                        _ => Some(s.to_owned()),
                    }
                }),
                friendly_name: grp.at(4).and_then(|s| {
                    match s {
                        "" => None,
                        _ => Some(s.to_owned()),
                    }
                }),
                addresses: grp.at(6).and_then(|s| {
                    match s {
                        "" => None,
                        _ => Some(s.split(",").map(|t| t.to_owned()).collect()),
                    }
                }),
                is_loopback: grp.at(7).unwrap() == "loopback",
                capabilities: caps,
            };
            v.push(dev);
        }
        Ok(v)
    }

    /// Call dumpcap to query the given device for it's supported link-layer types and support for
    /// capturing in monitor-mode.
    ///
    /// The device is put into monitor-mode before querying available link-layer types if
    /// monitor_mode is true; this may cause the device to lose all currently active connections.
    pub fn query_capabilities(&self,
                              dev_name: &str,
                              monitor_mode: bool)
                              -> Result<DeviceCapabilities> {
        let mut args = vec!["-L", "-Z", "none", "-i", dev_name];
        if monitor_mode {
            args.push("-I")
        }
        let mut child = try!(process::Command::new(&self.executable)
                                 .args(&args)
                                 .args(&self.extra_args)
                                 .stdin(process::Stdio::null())
                                 .stdout(process::Stdio::piped())
                                 .stderr(process::Stdio::piped())
                                 .spawn());

        try!(PipeReader(child.stderr.take().unwrap()).wait_for_success_msg());

        let mut v = Vec::new();
        let mut reader = io::BufReader::new(child.stdout.take().unwrap()).lines();
        let can_rfmon = match reader.next() {
            Some(Ok(v)) => match v.as_ref() {
                "1" => true,
                "0" => false,
                _ => {
                    return Err(DumpcapError::new(ErrorKind::Internal,
                                                 format!("Expected 0 or 1 to indicate rfmon, \
                                                          got {}",
                                                         v)));
                }
            },
            Some(Err(v)) => {
                return Err(DumpcapError::from(v));
            }
            None => {
                return Err(DumpcapError::new(ErrorKind::DumpcapFailed, "No output from dumpcap"));
            }
        };
        for line_res in reader {
            let line = try!(line_res);
            if line == "" {
                break;
            }
            v.push(try!(parse_capabilities_line(&line)));
        }
        match child.wait() {
            Err(e) => Err(DumpcapError::from(e)),
            Ok(status) => {
                if status.success() {
                    Ok(DeviceCapabilities {
                        can_rfmon: can_rfmon,
                        llts: v,
                    })
                } else {
                    Err(DumpcapError::new(ErrorKind::DumpcapFailed,
                                          "Dumpcap had some output but exited with nonzero exit \
                                           status."))
                }
            }
        }
    }
}

fn parse_statistics(s: &str) -> Result<DeviceStats> {
    let mut items = s.split("\t");
    let dev_name = try!(items.next().ok_or("No device name in output")).to_owned();
    let pc = try!(try!(items.next().ok_or("No packet count in output")).parse());
    let dc = try!(try!(items.next().ok_or("No drop count in output")).parse());
    Ok(DeviceStats {
        name: dev_name,
        packet_count: pc,
        drop_count: dc,
    })
}

fn parse_capabilities_line(line: &str) -> Result<LinkLayerType> {
    let items = line.split("\t").collect::<Vec<_>>();
    if items.len() != 3 {
        return Err(DumpcapError::new(ErrorKind::Internal,
                                     "Expected three columns of data per row"));
    }
    Ok(LinkLayerType {
        dlt: try!(items[0].parse()),
        name: items[1].to_owned(),
        description: items[2].to_owned(),
    })
}

/// Reports the number of packets seen on the given interface
#[derive(Debug, PartialEq)]
pub struct DeviceStats {
    /// The name of the interface
    pub name: String,
    /// The absolute number of packets seen on this interface
    pub packet_count: u64,
    /// The absolute number of packets dropped unseen
    pub drop_count: u64,
}

/// An iterator over the messages coming from a capturing dumpcap sub-process
pub struct DumpcapIterator<MsgType> {
    child: process::Child,
    handler: Option<thread::JoinHandle<Result<()>>>,
    rx: mpsc::Receiver<MsgType>,
}

impl<MsgType> Drop for DumpcapIterator<MsgType> {
    fn drop(&mut self) {
        // Dumpcap might already have exited so the kill() could fail; maybe this error
        // should get
        // logged?
        let _ = self.child.kill();
        match self.handler.take() {
            None => {}
            Some(jh) => {
                assert!(jh.join().is_ok());
            }
        }
    }
}

impl<MsgType> Iterator for DumpcapIterator<MsgType> {
    type Item = Result<MsgType>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.rx.recv().ok() {
            Some(e) => Some(Ok(e)),
            None => {
                match self.child.wait() {
                    Err(e) => Some(Err(DumpcapError::from(e))),
                    Ok(status) => {
                        if status.success() {
                            self.handler
                                .take()
                                .and_then(|jh| {
                                    jh.join()
                                      .err()
                                      .and(Some(Err(DumpcapError::new(ErrorKind::Internal,
                                                                      "The thread parsing \
                                                                       dumpcap's output \
                                                                       panicked"))))
                                })
                        } else {
                            Some(Err(DumpcapError::new(ErrorKind::DumpcapFailed,
                                                       "Dumpcap quit with nonzero exit status")))
                        }
                    }
                }
            }
        }
    }
}

macro_rules! argument_setter {
    ( $( ($name:ident, $param:ident, $tybe:ty, $doc:expr) ),+ ) => {
        $(
            #[doc=$doc]
            pub fn $name(mut self, $param: $tybe) -> Self {
                self.$name = $param;
                self
            }
        )+
    };
}

macro_rules! add_int_args {
    ( $args:expr, $(($arg:expr, $value:expr)),+ ) => {{
            $(
                if $value != 0 {
                    $args.push($arg.to_string());
                    $args.push($value.to_string());
                }
            )+
        }
    };
}

macro_rules! add_bool_args {
    ( $args:expr, $(($arg:expr, $value:expr)),+ ) => {{
            $(
                if $value {
                    $args.push($arg.to_string());
                }
            )+
        }
    };
}

macro_rules! add_string_args {
    ( $args:expr, $( ($arg:expr, $value:expr) ),+ ) => {{
            $(
                if let Some(e) = $value {
                    $args.push($arg.to_string());
                    $args.push(e.to_string());
                }
            )+
        }
    };
    ( $args:expr, $prefix: expr, $( ($arg:expr, $value:expr) ),+ ) => {
        {
            $(
                if $value != 0 {
                    $args.push($prefix.to_string());
                    $args.push(format!("{}:{}", $arg, $value));
                }
            )+
        }
    };
}

/// Controls options mostly for capturing network traffic for a single device
#[derive(Debug)]
pub struct DeviceArguments {
    arg: Arguments,
    dev_name: String,
    capture_filter: Option<String>,
    disable_promiscuous_mode: bool,
    monitor_mode: bool,
    kernel_buffer_size: u64,
    link_layer_type: Option<String>,
    snapshot_length: u64,
    wifi_channel: Option<String>,
}

impl DeviceArguments {
    argument_setter!((monitor_mode, enable, bool, "Enable monitor mode if available"));

    fn build(mut self) -> Arguments {
        let mut args = Vec::new();

        add_int_args!(args,
                      ("-B", self.kernel_buffer_size),
                      ("-s", self.snapshot_length));
        add_string_args!(args,
                         ("-f", self.capture_filter),
                         ("-y", self.link_layer_type),
                         ("-k", self.wifi_channel));
        add_bool_args!(args,
                       ("-p", self.disable_promiscuous_mode),
                       ("-I", self.monitor_mode));

        if !args.is_empty() {
            self.arg.device_args.push("-i".to_owned());
            self.arg.device_args.push(self.dev_name);
            self.arg.device_args.extend(args.into_iter());
        }
        self.arg
    }
}

/// Supported file-formats while capturing traffic
#[allow(enum_variant_names)]
#[derive(Debug)]
pub enum FileFormats {
    /// Capture in PCAP-format
    PCAP,
    /// Capture in PCAPNG-format
    PCAPNG,
}

/// Controls options mostly for capturing network traffic
#[derive(Debug, Default)]
pub struct Arguments {
    buffered_bytes: u64,
    buffered_packets: u64,
    capture_filter: Option<String>,
    device_args: Vec<String>,
    disable_promiscuous_mode: bool,
    enable_group_access: bool,
    enable_monitor_mode: bool,
    file_format: Option<FileFormats>,
    file_name: Option<String>,
    kernel_buffer_size: u64,
    link_layer_type: Option<String>,
    snapshot_length: u64,
    stop_on_duration: u64,
    stop_on_files: u64,
    stop_on_filesize: u64,
    stop_on_packet_count: u64,
    switch_on_duration: u64,
    switch_on_files: u64,
    switch_on_filesize: u64,
    use_threads: bool,
    command: Option<String>,
    child_mode: bool,
}

impl Arguments {

    /// Add a list of arguments for the named device
    pub fn device_argument(self, dev_name: &str) -> DeviceArguments {
        DeviceArguments {
            arg: self,
            dev_name: dev_name.to_owned(),
            capture_filter: None,
            disable_promiscuous_mode: false,
            monitor_mode: false,
            kernel_buffer_size: 0,
            link_layer_type: None,
            snapshot_length: 0,
            wifi_channel: None,
        }
    }

    argument_setter!((buffered_bytes, bytes, u64, "Maximum number of bytes used for buffering packets within dumpcap"),
            (buffered_packets, number, u64, "Maximum number of packets buffered within dumpcap"),
            (capture_filter, filter, Option<String>, "Capture filter in libpcap filter syntax"),
            (disable_promiscuous_mode, disable, bool, "Do not capture in promiscuous mode"),
            (enable_group_access, enable, bool, "Enable group read access on the output file"),
            (enable_monitor_mode, enable, bool, "Enable monitor mode, if available"),
            (file_format, format, Option<FileFormats>, "Use this format for the savefile"),
            (file_name, name, Option<String>, "Name of file to save"),
            (kernel_buffer_size, mib, u64, "Size of kernel buffer in MiB"),
            (link_layer_type, name, Option<String>, "Link layer type"),
            (snapshot_length, bytes, u64, "Packet snapshot length"),
            (stop_on_duration, seconds, u64, "Stop after this number of seconds"),
            (stop_on_files, number, u64, "Stop after this number of files"),
            (stop_on_filesize, kilobytes, u64, "Stop after this number of KB"),
            (stop_on_packet_count, number, u64, "Stop after this number of packets"),
            (switch_on_duration, seconds, u64, "Switch to next file after this number of seconds"),
            (switch_on_files, number, u64, "Ringbuffer: Replace after this number of files"),
            (switch_on_filesize, kilobytes, u64, "Switch to next file after this number of KB"),
            (use_threads, enable, bool, "Use a separate thread per interface"));

    fn build(self) -> Vec<String> {
        let mut args = Vec::new();

        if let Some(c) = self.command {
            args.push(c.clone());
        }

        if self.child_mode {
            // TODO Windows is different here...
            args.push("-Z".to_owned());
            args.push("none".to_owned());
        }

        add_int_args!(args,
                      ("-C", self.buffered_bytes),
                      ("-N", self.buffered_packets),
                      ("-B", self.kernel_buffer_size),
                      ("-s", self.snapshot_length),
                      ("-c", self.stop_on_packet_count));
        add_string_args!(args,
                         ("-f", self.capture_filter),
                         ("-w", self.file_name),
                         ("-y", self.link_layer_type));
        add_string_args!(args,
                         "-a",
                         ("files", self.stop_on_files),
                         ("duration", self.stop_on_duration),
                         ("filesize", self.stop_on_filesize));
        add_string_args!(args,
                         "-b",
                         ("files", self.switch_on_files),
                         ("duration", self.switch_on_duration),
                         ("filesize", self.switch_on_filesize));
        add_bool_args!(args,
                       ("-p", self.disable_promiscuous_mode),
                       ("-g", self.enable_group_access),
                       ("-I", self.enable_monitor_mode),
                       ("-t", self.use_threads));

        if let Some(f) = self.file_format {
            args.push(match f {
                          FileFormats::PCAP => "-P",
                          FileFormats::PCAPNG => "-n",
                      }
                      .to_owned());
        }

        args.extend(self.device_args.into_iter());

        args
    }
}

/// The known device types like USB or WiFi
#[derive(Debug)]
pub enum DeviceType {
    /// Airpcap
    Airpcap,
    /// Bluetooth
    Bluetooth,
    /// Dialup
    Dialup,
    /// Pipe
    Pipe,
    /// Stdin
    Stdin,
    /// USB
    USB,
    /// Virtual
    Virtual,
    /// Wired
    Wired,
    /// Wireless
    Wireless,
    /// Unknown
    Unknown(Option<u8>),
}

impl<'a> From<&'a str> for DeviceType {
    fn from(u: &'a str) -> Self {
        match u {
            "0" => DeviceType::Wired,
            "1" => DeviceType::Airpcap,
            "2" => DeviceType::Pipe,
            "3" => DeviceType::Stdin,
            "4" => DeviceType::Bluetooth,
            "5" => DeviceType::Wireless,
            "6" => DeviceType::Dialup,
            "7" => DeviceType::USB,
            "8" => DeviceType::Virtual,
            e => DeviceType::Unknown(e.parse().ok()),
        }
    }
}

impl ToString for DeviceType {
    fn to_string(&self) -> String {
        match *self {
            DeviceType::Airpcap => "AIRPCAP",
            DeviceType::Bluetooth => "BLUETOOTH",
            DeviceType::Dialup => "DIALUP",
            DeviceType::Pipe => "PIPE",
            DeviceType::Stdin => "STDIN",
            DeviceType::USB => "USB",
            DeviceType::Virtual => "VIRTUAL",
            DeviceType::Wired => "WIRED",
            DeviceType::Wireless => "WIRELESS",
            DeviceType::Unknown(..) => "UNKNOWN",
        }
        .to_owned()
    }
}


/// A link-layer type known to dumpcap
#[derive(Debug, Clone, PartialEq)]
pub struct LinkLayerType {
    /// An opaque number identifying this LLT
    pub dlt: u64,
    /// The type's short name (e.g. "EN10MB")
    pub name: String,
    /// A human-readable name (e.g. "Ethernet")
    pub description: String,
}

/// A physical or virtual device that can used to capture network traffic
#[derive(Debug)]
pub struct Device {
    /// The device's type (e.g. USB)
    pub dev_type: DeviceType,
    /// The system's name for the device (e.g. "eth0")
    pub name: String,
    /// An opaque number identifying this device
    pub number: u64,
    /// The vendor name for this device
    pub vendor_name: Option<String>,
    /// A human-readable name for the device
    pub friendly_name: Option<String>,
    /// A vector of addresses the device is currently bound to
    pub addresses: Option<Vec<String>>,
    /// True if the device is a local loopback
    pub is_loopback: bool,
    /// A list of link-layers a device can capture traffic on
    pub capabilities: Option<DeviceCapabilities>,
}

/// The link-layers a device can capture traffic on
#[derive(Debug, Clone)]
pub struct DeviceCapabilities {
    /// True if the device can be put into monitor mode
    pub can_rfmon: bool,
    /// A list of supported link-layer types.
    /// The list depends on wether the device has been put
    /// into monitor mode (if applicable).
    pub llts: Vec<LinkLayerType>,
}

/// An incoming message from the dumpcap child-process
#[derive(Debug, PartialEq)]
pub enum Message {
    /// At least one of the given capture filters is invalid
    BadFilter(String),
    /// The absolute number of dropped packets
    DropCount(u64),
    /// General error
    Error((String, String)),
    /// Filename dumpcap has started writing to
    File(String),
    /// The number of packets recently written to the currently active file
    PacketCount(u64),
    /// General success
    Success(String),
}

/// Wrap another type that is io::Read so one can read parsed messages from the underlying stream
struct PipeReader<T>(T);

impl<T> PipeReader<T> where T: Read {
    /// Read a single message from the underlying stream
    ///
    /// Tries to read the header and the message body, will block until the message is available or
    /// IO fails.
    fn read_pipe_msg(&mut self) -> Result<Option<(u8, Vec<u8>)>> {
        let mut buffer = Vec::<u8>::with_capacity(4);
        match try!((&mut self.0).take(4).read_to_end(&mut buffer)) {
            0 => {
                return Ok(None);
            }
            1...3 => {
                return Err(DumpcapError::new(ErrorKind::InvalidMessage, "Header was too short"));
            }
            _ => {}
        }

        let msg_type = buffer[0];
        let msg_size: u32 = ((buffer[1] as u32) << 16) | ((buffer[2] as u32) << 8) |
                            (buffer[3] as u32);

        buffer = Vec::<u8>::with_capacity(msg_size as usize);
        if try!((&mut self.0).take(msg_size as u64).read_to_end(&mut buffer)) < msg_size as usize {
            return Err(DumpcapError::new(ErrorKind::InvalidMessage,
                                         "Message was shorter than header said it would be"));
        }
        Ok(Some((msg_type, buffer)))
    }

    fn msg_to_string(mut v: Vec<u8>) -> result::Result<String, string::FromUtf8Error> {
        if v.ends_with(&[0]) {
            v.pop();
        }
        String::from_utf8(v)
    }

    fn parse_pipe_msg(&mut self) -> Result<Option<Message>> {
        match try!(self.read_pipe_msg()) {
            None => Ok(None),
            Some((msg_type, msg)) => {
                match msg_type {
                    DROP_COUNT_MSG =>
                        Ok(Some(Message::DropCount(try!(try!(Self::msg_to_string(msg)).parse())))),
                    PACKET_COUNT_MSG =>
                        Ok(Some(Message::PacketCount(try!(try!(Self::msg_to_string(msg)).parse())))),
                    ERROR_MSG => {
                        let mut err_reader = PipeReader(io::Cursor::new(msg));
                        let err_msg1 = try!(try!(err_reader.read_pipe_msg())
                                     .ok_or(DumpcapError::new(ErrorKind::InvalidMessage,
                                                              "Error message missing part 1")))
                                           .1;
                        let err_msg2 = try!(try!(err_reader.read_pipe_msg())
                                     .ok_or(DumpcapError::new(ErrorKind::InvalidMessage,
                                                              "Error message missing part 2")))
                                           .1;
                        Ok(Some(Message::Error((try!(Self::msg_to_string(err_msg1)),
                                                try!(Self::msg_to_string(err_msg2))))))
                    }
                    FILE_MSG => Ok(Some(Message::File(try!(Self::msg_to_string(msg))))),
                    SUCCESS_MSG => Ok(Some(Message::Success(try!(Self::msg_to_string(msg))))),
                    BAD_FILTER_MSG => Ok(Some(Message::BadFilter(try!(Self::msg_to_string(msg))))),
                    _ => Err(DumpcapError::new(ErrorKind::InvalidMessage,
                                               format!("Unknown message type {}", msg_type))),
                }
            }
        }
    }

    fn wait_for_success_msg(&mut self) -> Result<()> {
        match try!(self.parse_pipe_msg()) {
            Some(Message::Success(..)) => Ok(()),
            Some(Message::Error(e)) => {
                let mut errmsg = e.0;
                errmsg.push_str(&(e.1));
                Err(DumpcapError::new(ErrorKind::DumpcapFailed, errmsg))
            }
            None => Err(DumpcapError::new(ErrorKind::DumpcapFailed, "No output from dumpcap")),
            Some(..) =>
                Err(DumpcapError::new(ErrorKind::InvalidMessage, "Unexpected message from dumpcap")),
        }
    }
}

impl<T> Iterator for PipeReader<T> where T: Read {
    type Item = Result<Message>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.parse_pipe_msg() {
            Err(e) => Some(Err(e)),
            Ok(v) => match v {
                Some(msg) => Some(Ok(msg)),
                None => None,
            },
        }
    }
}

#[test]
fn deserialize_pipe_messages() {
    for (stream, expected_messages) in vec![
        (vec![],
         vec![]),
        (vec![99, 0, 0, 0],
         vec![Err(())]),
        (vec![SUCCESS_MSG, 0, 0, 4, 70, 111, 111, 0, PACKET_COUNT_MSG, 0, 0, 3, 49, 50, 0, 0],
         vec![Ok(Message::Success("Foo".to_owned())),
              Ok(Message::PacketCount(12)),
              Err(())]),
        (vec![DROP_COUNT_MSG, 0, 0, 3, 50, 49, 0, FILE_MSG, 0, 0, 2, 70, 0, BAD_FILTER_MSG, 0, 0, 2, 70, 0],
         vec![Ok(Message::DropCount(21)),
              Ok(Message::File("F".to_owned())),
              Ok(Message::BadFilter("F".to_owned()))]),
        (vec![ERROR_MSG, 0, 0, 13, ERROR_MSG, 0, 0, 3, 70, 111, 0, ERROR_MSG, 0, 0, 2, 111, 0],
         vec![Ok(Message::Error((("Fo".to_owned(), "o".to_owned()))))]),
    ] {
        println!("Testing {:?}", stream);
        let mut i = 0;
        for (j, msg) in PipeReader(io::Cursor::new(stream)).enumerate() {
            println!("{:?} {:?}, {}", msg, expected_messages[j], j);
            match expected_messages[j] {
                Ok(ref ok) => { assert_eq!(&msg.unwrap(), ok) },
                Err(..) => { assert!(msg.is_err()) }
            }
            i = j;
        }
        if i + 1 < expected_messages.len() {
            panic!("Expected {} messages, got {}", expected_messages.len(), i + 1)
        }
    }
}

#[test]
fn wait_for_msg_err() {
    let r = PipeReader(io::Cursor::new(vec![ERROR_MSG, 0, 0, 13, ERROR_MSG, 0, 0, 3, 70, 111, 0,
                                            ERROR_MSG, 0, 0, 2, 111, 0]))
                .wait_for_success_msg();
    let err = r.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::DumpcapFailed);
    assert_eq!(err.description(), "Foo");
}

#[test]
fn build_args() {
    assert_eq!(&Arguments::default()
                    .buffered_bytes(123)
                    .capture_filter(Some("foobar".to_owned()))
                    .enable_monitor_mode(true)
                    .file_format(Some(FileFormats::PCAPNG))
                    .stop_on_duration(456)
                    .switch_on_files(789)
                    .link_layer_type(Some("llt".to_owned()))
                    .build()
                    .join(" "),
               "-C 123 -f foobar -y llt -a duration:456 -b files:789 -I -n");
    assert_eq!(&Arguments::default()
                    .use_threads(true)
                    .device_argument("eth1")
                    .monitor_mode(true)
                    .build()
                    .build()
                    .join(" "),
               "-t -i eth1 -I");
}

#[test]
fn error_description() {
    let s = "This is the error message";
    assert_eq!(DumpcapError::new(ErrorKind::Internal, s).description(), s);
}
