# Checklist for ippextractor

- [ ] Find way to parse out IPP stream as a whole!
    - Look for POST Headers, see if protocol is /ipp/print

- [ ] *Extract Meta-Infos*
    - [ ] From ipp request directly

    - [ ] From Create-Job

    - Look for IPP packets, check their flag defining operation and filter Create-Job-Attributes
    - Create meta-folder
    - Extract operation-attributes-tags and job-attributes-tags

    Structure:
    - POST-Header
    - Version: 2 bytes (02 00 = 2.0)
    - *Operation Type*: 2 bytes (00 05 = Create-Job -> see specs)
    - Request-Id (4 bytes) (00 00 00 04 = id 4)
    - 01 -> Indicates start of operation-attributes
        - 1 byte buffer
        - 2 bytes for length of key
        - x bytes key
        - 2 bytes for length of value
        - y bytes value
        - 1 byte buffer
        - 2 bytes for length of key
        - ...
    - 02 (no buffer!) -> Indicates start of job-attributes
        - Collection media-col => Find out how to parse this!
        - Same structure as before
    - 03 -> End-of-attributes tag

=> Create two separate parts in json: One part is from Create-Job, one part is from Send-Document

- [ ] Extract single-page small document (linux2.pcap, stream 16 -> testprint.txt/out.pdf)
- [ ] Extract single-page bigger document (linux3.pcap, stream 57 -> bjoa.py)
- [ ] Extract multi-page document (linux3.pcap, stream 16 -> out.bin)
- [ ] Unzip the captured (and possibly reassembled) packets
- [ ] Convert to ppm using [pwg2ppm](https://github.com/attah/ppm2pwg)


## Zukunft

- [ ] Unterstützung aller IPP Attribute -> Verschiedene Workflows je nach IPP-Version (und somit möglichen Tags)
- [ ] Unterstützung anderer Drucker-Protokolle: PCL3Gui, PCL3/4/5/6, PCL XL, LPD/LPR, AppSocket/port 9100/RAW, AirPrint

## Ressources

### IPP

- [RFC2911 (IPP/1.1)](https://datatracker.ietf.org/doc/html/rfc2911)
- [RFC 8010 (IPP/1.1)](https://datatracker.ietf.org/doc/html/rfc8011)
- [PWG 5100.12-2015 (IPP 2.0,2.1,2.2)] (https://ftp.pwg.org/pub/pwg/standards/std-ipp20-20151030-5100.12.pdf)
- [ppm2pwg Github](https://github.com/attah/ppm2pwg)

### Scapy/Wireshark

- [tshark examples](https://www.razorcodes.com/2018/02/12/capture_save_and_resend_requests_with_Wireshark.html)
