```
                      ____             _       _    _       _     
 _ __   ___ __ _ _ __|___ \ _ __  _ __(_)_ __ | |_ (_) ___ | |__  
| '_ \ / __/ _` | '_ \ __) | '_ \| '__| | '_ \| __|| |/ _ \| '_ \ 
| |_) | (_| (_| | |_) / __/| |_) | |  | | | | | |_ | | (_) | |_) |
| .__/ \___\__,_| .__/_____| .__/|_|  |_|_| |_|\__|/ |\___/|_.__/ 
|_|             |_|        |_|                   |__/             

pcap2printjob by mightychoc
github.com/mightychoc/pcap2printjob

```

![Static Badge](https://img.shields.io/badge/IPP-2.0-008000?style=for-the-badge)

`pcap2printjob` is a tool for reversing print jobs from captured network traffic. It currently supports unencrypted CUPS IPP 2.0 traffic, but it is planed to extend the tool for other printing protocols in the future.

### Dependencies and Used Technologies

- [Scapy](https://scapy.net/) - Python library for packet manipulation
- [ppm2pwg](https://github.com/attah/ppm2pwg) - Open source PWG/URF to Netpbm converter
- [Wireshark / tshark](https://www.wireshark.org/) - Network protocol analyser

## Improvements

### IPP 2.0

- [ ] `pcap2printjob` cannot parse the job-attributes media struct in the IPP create-job request. Hence we simply skip this information at the moment...
- [ ] Unknown what happens to the program, if the TCP-footer is not empty
- [ ] There are other possible tags which IPP can set according to the specification. Unclear how we can handle this due to lack of testing data.

### General

- [ ] Use multithreading to process multiple pcap files / multiple jobs in a pcap file in parallel.
- [ ] "Magic mode" to identify which protocols might even be present in a given pcap file. This can be done by looking for specific destination ports (9100, 631...)
