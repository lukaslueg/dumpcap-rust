use std::process;
use std::env;

fn main() {
    env::set_current_dir("tests/mock_dumpcap").unwrap();
    if !process::Command::new("cargo").arg("build").output().unwrap().status.success() {
        panic!("Failed to build mock_dumpcap");
    }
}
