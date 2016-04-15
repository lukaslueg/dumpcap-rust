extern crate dumpcap;

fn main() {
    let d = dumpcap::Dumpcap::default();
    println!("{}", d.version_string().unwrap());

    for msg in d.capture_iter(dumpcap::Arguments::default()
                                  .file_name(Some("/tmp/wireshark_foo".to_string()))
                                  .switch_on_duration(2)
                                  .stop_on_duration(20)) {
        let msg = msg.unwrap();
        match msg {
            dumpcap::Message::File(filename) => {
                println!("Ready to read from {}", filename);
            }
            dumpcap::Message::PacketCount(count) => {
                println!("Ready to read {} packets", count);
            }
            dumpcap::Message::DropCount(count) => {
                println!("A total of {} packets were dropped", count);
            }
            dumpcap::Message::BadFilter(err) => {
                panic!(err);
            }
            dumpcap::Message::Error((mut err1, err2)) => {
                err1.push_str(&err2);
                panic!(err1);
            }
            dumpcap::Message::Success(..) => {}
        }
    }
}
