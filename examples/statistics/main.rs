extern crate dumpcap;

fn main() {
    let d = dumpcap::Dumpcap::default();
    println!("{}", d.version_string().unwrap());

    println!("Interface\tReceived\tDropped");
    let (mut child, handler) = d.statistics(|stats| {
                                    println!("{}\t{}\t{}",
                                             stats.name,
                                             stats.packet_count,
                                             stats.drop_count)
                                })
                                .unwrap();
    assert!(child.wait().unwrap().success());
    assert!(handler.join().is_ok());
}
