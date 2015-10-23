extern crate dumpcap;

fn main() {
    let d = dumpcap::Dumpcap::new();
    println!("{}", d.version_string().unwrap());

    println!("No.\tName\tWifi?\tLinkLayer");
    for (i, dev) in d.query_devices(true).unwrap().into_iter().enumerate() {
        match dev.capabilities {
            Some(caps) => {
                println!("{}.\t{}\t{}\t{}", i, dev.name,
                        match caps.can_rfmon { true => "Yes", false => "No" },
                        caps.llts[0].name);
            },
            None => {
                println!("{}.\t{}\t?\t?", i, dev.name);
            }
        }
    }
}
