dumpcap
=======

Provides an interface to [Wireshark](https://www.wireshark.org)'s `dumpcap` tool for the rust programming language.

You can use `dumpcap` to
* find out about available network interfaces and their supported capabilities. See [here](https://github.com/lukaslueg/dumpcap-rust/blob/master/examples/devices/main.rs) for an example.
* Receive live statistics about traffic seen on each interface. See  [here](https://github.com/lukaslueg/dumpcap-rust/blob/master/examples/statistics/main.rs) for example.
* Capture traffic and save it to disk for further processing. See [here](https://github.com/lukaslueg/dumpcap-rust/blob/master/examples/capture_state/main.rs) for an example.

On most BSD/Linux distributions `dumpcap` comes suid'd so one can capture traffic using this isolated single-purpose process and does not need root credibilities to dissect captured traffic.


[![Build Status](https://travis-ci.org/lukaslueg/dumpcap-rust.svg?branch=master)](https://travis-ci.org/lukaslueg/dumpcap-rust)
