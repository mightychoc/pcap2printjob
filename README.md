# Checklist for ippextractor

- [ ] Make sure pwg2ppm is installed on setup!

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


## Current Problems

- We cannot parse the job-attributes media struct in the IPP create-job request. Hence we simply skip this information at the moment...


## Zukunft

- [ ] Unterstützung aller IPP Attribute -> Verschiedene Workflows je nach IPP-Version (und somit möglichen Tags)
- [ ] Unterstützung anderer Drucker-Protokolle: PCL3Gui, PCL3/4/5/6, PCL XL, LPD/LPR, AppSocket/port 9100/RAW, AirPrint
- [ ] Nutze Multithreading, damit die einzelnen Druckaufträge parallel prozessiert werden können (Single-Thread extraktion aus base-pcap, einzelne Druckaufträge dann auf mehrere Threads aufteilen)
    - [ ] Erlauben, dass man eine Liste von Files hineinlädt, diese auch mit Multithreading abarbeiten
- [ ] Suche nach mehreren Protokollen gleichzeitig -> Identifiziere die Jobs und gib Übersicht über gefundene Jobs (Liste mit x IPP, y AirPrint, z PCL XL...) => "Magic Mode"

## Ressources

### IPP

- [RFC2911 (IPP/1.1)](https://datatracker.ietf.org/doc/html/rfc2911)
- [RFC 8010 (IPP/1.1)](https://datatracker.ietf.org/doc/html/rfc8011)
- [PWG 5100.12-2015 (IPP 2.0,2.1,2.2)] (https://ftp.pwg.org/pub/pwg/standards/std-ipp20-20151030-5100.12.pdf)
- [ppm2pwg Github](https://github.com/attah/ppm2pwg)

### Scapy/Wireshark

- [tshark examples](https://www.razorcodes.com/2018/02/12/capture_save_and_resend_requests_with_Wireshark.html)


# Binary findings

Data starts like this:
- 1 Chunk POST-Request ending in 0d0a0d0a [PSH, ACK]
- 1 Chunk Job-Attributes [PSH, ACK]
- 1 Chunk delimiter 0d0a [PSH, ACK]
- (1 ACK Frame)
- 1 Frame telling size of data to expect, ending in 0d0a [PSH, ACK]
- x Frames Actual gzip data, starting with 1f8b. Chunks are separated by 0d0a. The last chunk ends in 0d0a.
    - 313 30 30 30 0d 0a = 10'000 is maximal chunk size!
    - Each individual chunk also ends in 0d0a! Strip this, if necsesary
- End of chunk encoding (30 0d 0a = 0 octets)
- 0d 0a to show end of transmission/end of last chunk



- HTTP Chunk boundary is 0d 0a
- End of chunked encoding: 30 0d 0a 0d 0a

# pcap2job

## Used technologies

Give a little technical overview, of how the program works:

- Use scapy and tshark to exfiltrate the ipp (and possibly other) streams based on identifiers
- Use Scapy to exfiltrate meta data and raw package load
- Reassemble the packages if necessary
- Unzip the payload/postprocess to convertible format
- Convert the binary format to human readable format (ppm2pwg, ghostscript...)

- Wireshark/tshark
- ppm2pwg
- Scapy







1. Get POST-request before create-job
2. Get create-job packet
3. Get POST-request of send-document
4. Grab all packets until EOT
    4.1 Watch out for embedded EOT...