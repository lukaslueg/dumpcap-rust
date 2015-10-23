use std::env;
use std::sync;
use std::error::Error;

extern crate dumpcap;

enum FailMode {
    Fast,
    Normal,
    Illegal,
    BadFilter
}

fn get_mock(fail_mode: Option<FailMode>) -> dumpcap::Dumpcap {
    let mock = env::current_dir().unwrap().join("tests/mock_dumpcap/target/debug/mock_dumpcap");
    let mut d = dumpcap::Dumpcap::new_with_executable(mock);
    if let Some(m) = fail_mode {
        d.extra_args = vec![match m {
            FailMode::Fast => "--DUMPCAP_MOCK_FAIL_FAST",
            FailMode::Normal => "--DUMPCAP_MOCK_FAIL_NORMAL",
            FailMode::Illegal => "--DUMPCAP_MOCK_FAIL_ILLEGAL",
            FailMode::BadFilter => "--DUMPCAP_MOCK_FAIL_FILTER"
        }.to_string()];
    }
    d
}

#[test]
fn version_string() {
    assert_eq!(get_mock(None).version_string().unwrap(),
               "Mocked dumpcap");
}

#[test]
fn verstion_string_fail_fast() {
    let f = get_mock(Some(FailMode::Fast)).version_string().unwrap_err();
    assert_eq!(f.kind(), dumpcap::ErrorKind::DumpcapFailed);
    assert_eq!(f.description(), "Mock failed as it should");
}

#[test]
fn interfaces() {
    let ifaces = get_mock(None).query_devices(true).unwrap();
    assert_eq!(ifaces.len(), 2);

    let em1 = &ifaces[0];
    assert_eq!(em1.dev_type.to_string(), "WIRED");
    assert_eq!(em1.name, "em1");
    assert_eq!(em1.number, 1);
    assert!(em1.vendor_name.is_none());
    assert!(em1.friendly_name.is_none());
    assert!(em1.addresses.is_none());
    assert!(!em1.is_loopback);
    let em1_caps = em1.capabilities.clone().unwrap();
    assert!(em1_caps.can_rfmon);
    assert_eq!(em1_caps.llts, vec![dumpcap::LinkLayerType { dlt: 1,
                                                            name: "EN10MB".to_owned(),
                                                            description: "Ethernet".to_owned() },
                                   dumpcap::LinkLayerType { dlt: 143,
                                                            name: "DOCSIS".to_owned(),
                                                            description: "DOCSIS".to_owned() }]);
    let lo = &ifaces[1];
    assert_eq!(lo.dev_type.to_string(), "WIRED");
    assert_eq!(lo.name, "lo");
    assert_eq!(lo.number, 2);
    assert!(lo.vendor_name.is_none());
    assert_eq!(lo.friendly_name.clone().unwrap(), "Loopback");
    assert_eq!(lo.addresses.clone().unwrap(), vec!["127.0.0.1", "::1"]);
    assert!(lo.is_loopback);
    let lo_caps = lo.capabilities.clone().unwrap();
    assert!(!lo_caps.can_rfmon);
    assert_eq!(lo_caps.llts, vec![dumpcap::LinkLayerType { dlt: 1,
                                                           name: "EN10MB".to_owned(),
                                                           description: "Ethernet".to_owned() }]);
}

#[test]
fn interfaces_fail_fast() {
    let f = get_mock(Some(FailMode::Fast)).query_devices(false).unwrap_err();
    assert_eq!(f.kind(), dumpcap::ErrorKind::DumpcapFailed);
    assert_eq!(f.description(), "Mock failed as it should");
}

#[test]
fn interfaces_fail_illegal() {
    let ifaces = get_mock(Some(FailMode::Illegal)).query_devices(false).unwrap();
    assert_eq!(ifaces.len(), 0);
}


#[test]
fn capabilities_fail_fast() {
    let f = get_mock(Some(FailMode::Fast)).query_capabilities("foo1").unwrap_err();
    assert_eq!(f.kind(), dumpcap::ErrorKind::DumpcapFailed);
    assert_eq!(f.description(), "No output from dumpcap");
}

#[test]
fn capabilities_fail_illegal() {
    let f = get_mock(Some(FailMode::Illegal)).query_capabilities("foo1").unwrap_err();
    assert_eq!(f.kind(), dumpcap::ErrorKind::Internal);
}

#[test]
fn capabilities_fail_normal() {
    assert_eq!(get_mock(Some(FailMode::Normal)).query_capabilities("foo1").unwrap_err().kind(),
               dumpcap::ErrorKind::DumpcapFailed);
}

#[test]
fn statistics() {
    let expected = sync::Arc::new(sync::Mutex::new(
            vec![dumpcap::DeviceStats{ name: "foo1".to_string(), packet_count: 4711, drop_count: 123 },
                 dumpcap::DeviceStats{ name: "bar2".to_string(), packet_count: 4811, drop_count: 456 }].into_iter()));
    let cb_fix =  expected.clone();
    let callback = move |s| {
        if let Some(fix) = cb_fix.lock().unwrap().next() {
            assert_eq!(s, fix);
        }
    };
    let (mut child, handler) = get_mock(None).statistics(callback).unwrap();
    assert!(child.wait().unwrap().success());
    assert!(handler.join().is_ok());
    assert!(expected.lock().unwrap().next().is_none());
}

#[test]
fn statistics_fail_fast() {
    if let Err(f) = get_mock(Some(FailMode::Fast)).statistics(|_| ()) {
        assert_eq!(f.kind(), dumpcap::ErrorKind::DumpcapFailed);
    } else {
        panic!("Error expected");
    }
}

#[test]
fn statistics_fail_normal() {
    let (mut child, handler) = get_mock(Some(FailMode::Normal)).statistics(|_| ()).unwrap();
    assert!(!child.wait().unwrap().success());
    assert!(handler.join().unwrap().is_ok());
}

#[test]
fn statistics_fail_illegal() {
    let (mut child, handler) = get_mock(Some(FailMode::Illegal)).statistics(|_| ()).unwrap();
    assert!(child.wait().unwrap().success());
    handler.join().unwrap().unwrap_err();
}

#[test]
fn statistics_iter() {
    let mut got = get_mock(None).stats_iter().into_iter();
    assert_eq!(got.next().unwrap().unwrap(), dumpcap::DeviceStats { name: "foo1".to_string(), packet_count: 4711, drop_count: 123 });
    assert_eq!(got.next().unwrap().unwrap(), dumpcap::DeviceStats { name: "bar2".to_string(), packet_count: 4811, drop_count: 456 });
    assert!(got.next().is_none());
}

#[test]
fn capture() {
    let expected = sync::Arc::new(sync::Mutex::new(
            vec![dumpcap::Message::File("foo.filename".to_string()),
                 dumpcap::Message::PacketCount(123),
                 dumpcap::Message::DropCount(456)].into_iter()));
    let cb_fix = expected.clone();
    let callback = move |m| {
        assert_eq!(m, cb_fix.lock().unwrap().next().unwrap());
    };
    let (mut child, handler) = get_mock(None).capture(dumpcap::Arguments::default(),
                                                      callback).unwrap();
    assert!(child.wait().unwrap().success());
    assert!(handler.join().is_ok());
    assert!(expected.lock().unwrap().next().is_none());
}

#[test]
fn capture_fail_fast() {
    let (mut child, handler) = get_mock(Some(FailMode::Fast)).capture(dumpcap::Arguments::default(),
                                                                      |_| ()).unwrap();
    assert!(!child.wait().unwrap().success());
    handler.join().unwrap().unwrap();
}

#[test]
fn capture_fail_illegal() {
    let (mut child, handler) = get_mock(Some(FailMode::Illegal)).capture(dumpcap::Arguments::default(),
                                                                         |_| ()).unwrap();
    assert!(child.wait().unwrap().success());
    handler.join().unwrap().unwrap_err();
}

#[test]
fn capture_fail_filter() {
    let (mut child, handler) = get_mock(Some(FailMode::BadFilter)).capture(dumpcap::Arguments::default(),
                                                                           |_| ()).unwrap();
    assert!(!child.wait().unwrap().success());
    handler.join().unwrap().unwrap();
}

#[test]
fn capture_fail_normal() {
    let (mut child, handler) = get_mock(Some(FailMode::Normal)).capture(dumpcap::Arguments::default(),
                                                                        |_| ()).unwrap();
    assert!(!child.wait().unwrap().success());
    handler.join().unwrap().unwrap();
}
