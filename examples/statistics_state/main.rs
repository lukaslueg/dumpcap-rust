use std::sync::mpsc;

extern crate dumpcap;

fn main() {
    let d = dumpcap::Dumpcap::default();
    println!("{}", d.version_string().unwrap());

    let (tx, rx) = mpsc::channel();
    let (mut child, handler) = d.statistics(move |s| tx.send(s).unwrap()).unwrap();
    for s in rx {
        println!("{}\t{}\t{}", s.name, s.packet_count, s.drop_count);
    }
    assert!(child.wait().unwrap().success());
    assert!(handler.join().is_ok());
}
