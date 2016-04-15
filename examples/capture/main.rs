extern crate dumpcap;

fn main() {
    let d = dumpcap::Dumpcap::default();
    println!("{}", d.version_string().unwrap());

    let (mut child, handler) = d.capture(dumpcap::Arguments::default().stop_on_duration(20),
                                         |msg| println!("{:?}", msg))
                                .unwrap();
    assert!(child.wait().unwrap().success());
    assert!(handler.join().is_ok());
}
