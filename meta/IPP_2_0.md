# IPP 2.0

The following analysis are my findings on the essentials of IPP - I do not guarantee completeness or correctness in any way. This document solely serves the purpose to help understand my line of thought in creation of the parser and to collect the information gathered during development.

## Packets sent

Opening up a collected stream in Wireshark reveals that various TCP connections are established before the actual print job is sent. The communication happens via HTTP POST requests. First, the host introduces itself and sends an IPP `Get-Printer-Attributes` packet to the printer. This packet contains various meta information like the host and printer URIs, the character encoding and the requesting user name. The printer responds with a status code of 100 (Continue) and acknwoledges the end of the host-sent data with a response of 200. It then sends the printer attributes like the transfer-encoding it intends to use or the supported document formats. These conversations seem to fulfill the purpose of clarifiying the capabilities of the host and the printer. Multiple of these `Get-Printer-Attributes` conversations can be observed in advance of the actual print job.

Next, an IPP `Create-Job` request is sent from the host to the printer. It contains the specific operation attributes and job attributes used for the following document transfer. Again, it follows the HTTP POST-100-200 pattern.

Lastly, the host sends an IPP `Send-Document` request. It starts again with a HTTP POST request and a meta data packet, before the printer responds with a HTTP 100 message. Then, the document is sent in one ore more chunks. Finally, the printer responds with a status code of 200 and acknowledges some meta information like the job-ID.

After the print job has been sent, we can observe an alternating pattern of IPP `Get-Printer-Attributes` and `Get-Job-Attributes` request. Analogous to before, these are requests from the host to the printer which asks for metadata on the printer or the jobs. The `pcap2printjob` parser ignores these `Get-Printer-Attributes` and `Get-Job-Attributes` conversations as they do not contain a lot of specific data to the printed job itself. And information like the user issuing the print are also included in the `Create-Job` and `Send-Document` request.

## Hexdump Analysis - IPP over HTTP

The following hexdumps are the TCP payloads of the data sent by the host to the printer. It can be obtained by using Wireshark's "Follow TCP Stream" utility or by issuing Scapy's `packet[Raw].load` in combination with `xxd` or `hexdump`.

### Create-Job request

The IPP `Create-Job` request consists of various packets. Each logical segment in the TCP stream ends with the bytes `0d 0a`.

```
00000000  50 4f 53 54 20 2f 69 70  70 2f 70 72 69 6e 74 20   POST /ip p/print 
00000010  48 54 54 50 2f 31 2e 31  0d 0a 43 6f 6e 74 65 6e   HTTP/1.1 ..Conten
00000020  74 2d 4c 65 6e 67 74 68  3a 20 36 30 33 0d 0a 43   t-Length : 603..C
00000030  6f 6e 74 65 6e 74 2d 54  79 70 65 3a 20 61 70 70   ontent-T ype: app
00000040  6c 69 63 61 74 69 6f 6e  2f 69 70 70 0d 0a 44 61   lication /ipp..Da
00000050  74 65 3a 20 4d 6f 6e 2c  20 31 30 20 4a 61 6e 20   te: Mon,  01 Jan 
00000060  31 39 39 30 20 30 30 3a  30 30 3a 30 30 20 47 4d   1990 00: 00:00 GM
00000070  54 0d 0a 48 6f 73 74 3a  20 XX XX XX XX XX XX XX   T..Host:  XXXXXXX
00000080  XX XX XX XX XX XX XX 2e  6c 6f 63 61 6c 3a 36 33   XXXXXXX. local:63
00000090  31 0d 0a 55 73 65 72 2d  41 67 65 6e 74 3a 20 43   1..User- Agent: C
000000A0  55 50 53 2f 32 2e 34 2e  37 20 28 4c 69 6e 75 78   UPS/2.4. 7 (Linux
000000B0  20 36 2e 38 2e 30 2d 33  35 2d 67 65 6e 65 72 69    6.8.0-3 5-generi
000000C0  63 3b 20 78 38 36 5f 36  34 29 20 49 50 50 2f 32   c; x86_6 4) IPP/2
000000D0  2e 30 0d 0a 45 78 70 65  63 74 3a 20 31 30 30 2d   .0..Expe ct: 100-
000000E0  63 6f 6e 74 69 6e 75 65  0d 0a 0d 0a               continue ....
```

This first packet is easily recognised as the initial POST request. It consists of key-value fields, separated by the bytes `0d 0a` (which translates to a carriage return followed by a newline). Notice how the last four bytes are `0d 0a 0d 0a`, where the first two bytes mark the end of the Expect: 100-continue field and the last two bytes mark the end of the logical POST-request segment.

Next, we have the actual `Create-Job` payload. Its structure is as follows:

- The first two bytes indicate the IPP version. In our case, `02 00` indicates IPP 2.0. and e.g. `01 01` would indicate IPP 1.1.
- The next two bytes indicate the IPP operation. Here, `00 05` indicates that this is a `Create-Job` request. An overview on the operation IDs can be found [here (p.16-21)](https://ftp.pwg.org/pub/pwg/standards/std-ipp20-20151030-5100.12.pdf).
- Following up, we have four bytes forming the request ID. In our case, this is `00 00 00 04`, representing the request with ID 4.
- We encounter the byte `01` indicating the beginning of the operation attributes.
- The operation attributes follow similar to before as key-value pairs.
- After the last operation attribute, the byte `02` represents the beginning of the job attributes.
- The job attributes also consist of a "media-struct" and some key-value pairs.
- The attributes are closed with the end-of-attributes tag, namely the byte `03`.

```
000000EC  02 00 00 05 00 00 00 04  
                                   01 47 00 12 61 74 74 72   ........ .G..attr
000000FC  69 62 75 74 65 73 2d 63  68 61 72 73 65 74 00 05   ibutes-c harset..
0000010C  75 74 66 2d 38 48 00 1b  61 74 74 72 69 62 75 74   utf-8H.. attribut
0000011C  65 73 2d 6e 61 74 75 72  61 6c 2d 6c 61 6e 67 75   es-natur al-langu
0000012C  61 67 65 00 05 65 6e 2d  75 73 45 00 0b 70 72 69   age..en- usE..pri
0000013C  6e 74 65 72 2d 75 72 69  00 28 69 70 70 3a 2f 2f   nter-uri .(ipp://
0000014C  XX XX XX XX XX XX XX XX  XX XX XX XX XX XX 2e 6c   XXXXXXXX XXXXXX.l
0000015C  6f 63 61 6c 3a 36 33 31  2f 69 70 70 2f 70 72 69   ocal:631 /ipp/pri
0000016C  6e 74 42 00 14 72 65 71  75 65 73 74 69 6e 67 2d   ntB..req uesting-
0000017C  75 73 65 72 2d 6e 61 6d  65 00 05 63 68 6f 63 6f   user-nam e..choco
0000018C  42 00 08 6a 6f 62 2d 6e  61 6d 65 00 18 67 6e 6f   B..job-n ame..gno
0000019C  6d 65 2d 74 65 78 74 2d  65 64 69 74 6f 72 20 6a   me-text- editor j
000001AC  6f 62 20 23 33 
                         02 34 00  09 6d 65 64 69 61 2d 63   ob #3.4. .media-c
000001BC  6f 6c 00 00 4a 00 00 00  0a 6d 65 64 69 61 2d 73   ol..J... .media-s
000001CC  69 7a 65 34 00 00 00 00  4a 00 00 00 0b 78 2d 64   ize4.... J....x-d
000001DC  69 6d 65 6e 73 69 6f 6e  21 00 00 00 04 00 00 54   imension !......T
000001EC  56 4a 00 00 00 0b 79 2d  64 69 6d 65 6e 73 69 6f   VJ....y- dimensio
000001FC  6e 21 00 00 00 04 00 00  6d 24 37 00 00 00 00 4a   n!...... m$7....J
0000020C  00 00 00 0a 6d 65 64 69  61 2d 74 79 70 65 44 00   ....medi a-typeD.
0000021C  00 00 0a 73 74 61 74 69  6f 6e 65 72 79 4a 00 00   ...stati oneryJ..
0000022C  00 10 6d 65 64 69 61 2d  74 6f 70 2d 6d 61 72 67   ..media- top-marg
0000023C  69 6e 21 00 00 00 04 00  00 01 28 4a 00 00 00 11   in!..... ..(J....
0000024C  6d 65 64 69 61 2d 6c 65  66 74 2d 6d 61 72 67 69   media-le ft-margi
0000025C  6e 21 00 00 00 04 00 00  01 28 4a 00 00 00 12 6d   n!...... .(J....m
0000026C  65 64 69 61 2d 72 69 67  68 74 2d 6d 61 72 67 69   edia-rig ht-margi
0000027C  6e 21 00 00 00 04 00 00  01 28 4a 00 00 00 13 6d   n!...... .(J....m
0000028C  65 64 69 61 2d 62 6f 74  74 6f 6d 2d 6d 61 72 67   edia-bot tom-marg
0000029C  69 6e 21 00 00 00 04 00  00 01 28 37 00 00 00 00   in!..... ..(7....
000002AC  44 00 0a 6f 75 74 70 75  74 2d 62 69 6e 00 07 66   D..outpu t-bin..f
000002BC  61 63 65 2d 75 70 44 00  10 70 72 69 6e 74 2d 63   ace-upD. .print-c
000002CC  6f 6c 6f 72 2d 6d 6f 64  65 00 05 63 6f 6c 6f 72   olor-mod e..color
000002DC  23 00 0d 70 72 69 6e 74  2d 71 75 61 6c 69 74 79   #..print -quality
000002EC  00 04 00 00 00 04 44 00  05 73 69 64 65 73 00 09   ......D. .sides..
000002FC  6f 6e 65 2d 73 69 64 65  64 44 00 1a 6d 75 6c 74   one-side dD..mult
0000030C  69 70 6c 65 2d 64 6f 63  75 6d 65 6e 74 2d 68 61   iple-doc ument-ha
0000031C  6e 64 6c 69 6e 67 00 22  73 65 70 61 72 61 74 65   ndling." separate
0000032C  2d 64 6f 63 75 6d 65 6e  74 73 2d 63 6f 6c 6c 61   -documen ts-colla
0000033C  74 65 64 2d 63 6f 70 69  65 73 03                  ted-copi es.
```

It is worth noting that the key-value pairs follow a certain structure. As an example, we analyse the first operation attribute. We can split the whole key-value pair into five parts:

```
47
00 12
61 74 74 72 69 62 75 74 65 73 2d 63 68 61 72 73 65 74
00 05
75 74 66 2d 38
```

- `47` seems to be some kind of key/category for the following key-value pair. However, so far I did not find out the exact meaning of these bytes.
- `00 12` indicates the length of the following key. Converting `0x12` to decimal, this gives 18...
- ... corresponding to the 18 bytes needed to form "attributes-charset".
- `00 05` again indicates the length of the five bytes which form the value "utf-8".

This pattern is consistent for all key-value pairs observed, in the `Create-Job` request as well as in the `Send-Document` header.

### Send-Document request

The `Send-Document` request in starts analogously to the `Create-Job` transmission. First, a POST request is issued, containing key-value pairs separated by `0d 0a`. Next, as `Transfer-Encoding` is specified as `chunked`, we have a packet containing `66 34 0d 0a`. This packet specifies the length of the next data chunk: `66 34` translates to `0xf4` which in decimal is 244 - which corresponds to the length of 244 bytes. Next, we again have two bytes for the IPP version (`02 00`), two bytes for the IPP operation (`00 06` meaning `Send-Document`) and four bytes indicating the request ID (`00 00 00 05`). Again, `01` marks the beginning of the operation attributes. However, this time, we directly have a end-of-attributes tag `03` and no job attributes specified. Furthermore, notice how every chunk/packet is again separated by `0d 0a`.


          4d 6f 6e 2c  20 31 30 20 4a 61 6e 20   te: Mon,  01 Jan 
00000060  31 39 39 30 20 30 30 3a  30 30 3a 30 30 20 47 4d   1990 00: 00:00 GM
00000070  54

```
00000000  50 4f 53 54 20 2f 69 70  70 2f 70 72 69 6e 74 20   POST /ip p/print 
00000010  48 54 54 50 2f 31 2e 31  0d 0a 43 6f 6e 74 65 6e   HTTP/1.1 ..Conten
00000020  74 2d 54 79 70 65 3a 20  61 70 70 6c 69 63 61 74   t-Type:  applicat
00000030  69 6f 6e 2f 69 70 70 0d  0a 44 61 74 65 3a 20 4d   ion/ipp. .Date: M
00000040  6f 6e 2c 20 31 30 20 4a  61 6e 20 31 39 39 30 20   on, 01 J an 1990 
00000050  30 30 3a 30 30 3a 30 30  20 47 4d 54 0d 0a 48 6f   00:00:00  GMT..Ho
00000060  73 74 3a 20 XX XX XX XX  XX XX XX XX XX XX XX XX   st: XXXX XXXXXXXX
00000070  XX XX 2e 6c 6f 63 61 6c  3a 36 33 31 0d 0a 54 72   XX.local :631..Tr
00000080  61 6e 73 66 65 72 2d 45  6e 63 6f 64 69 6e 67 3a   ansfer-E ncoding:
00000090  20 63 68 75 6e 6b 65 64  0d 0a 55 73 65 72 2d 41    chunked ..User-A
000000A0  67 65 6e 74 3a 20 43 55  50 53 2f 32 2e 34 2e 37   gent: CU PS/2.4.7
000000B0  20 28 4c 69 6e 75 78 20  36 2e 38 2e 30 2d 33 35    (Linux  6.8.0-35
000000C0  2d 67 65 6e 65 72 69 63  3b 20 78 38 36 5f 36 34   -generic ; x86_64
000000D0  29 20 49 50 50 2f 32 2e  30 0d 0a 45 78 70 65 63   ) IPP/2. 0..Expec
000000E0  74 3a 20 31 30 30 2d 63  6f 6e 74 69 6e 75 65 0d   t: 100-c ontinue.
000000F0  0a 0d 0a                                           ...

000000F3  66 34 0d 0a 

                      02 00 00 06  00 00 00 05 01 47 00 12   f4...... .....G..
00000103  61 74 74 72 69 62 75 74  65 73 2d 63 68 61 72 73   attribut es-chars
00000113  65 74 00 05 75 74 66 2d  38 48 00 1b 61 74 74 72   et..utf- 8H..attr
00000123  69 62 75 74 65 73 2d 6e  61 74 75 72 61 6c 2d 6c   ibutes-n atural-l
00000133  61 6e 67 75 61 67 65 00  05 65 6e 2d 75 73 45 00   anguage. .en-usE.
00000143  0b 70 72 69 6e 74 65 72  2d 75 72 69 00 28 69 70   .printer -uri.(ip
00000153  70 3a 2f 2f XX XX XX XX  XX XX XX XX XX XX XX XX   p://XXXX XXXXXXXX
00000163  XX XX 2e 6c 6f 63 61 6c  3a 36 33 31 2f 69 70 70   XX.local :631/ipp
00000173  2f 70 72 69 6e 74 21 00  06 6a 6f 62 2d 69 64 00   /print!. .job-id.
00000183  04 00 00 00 0b 42 00 14  72 65 71 75 65 73 74 69   .....B.. requesti
00000193  6e 67 2d 75 73 65 72 2d  6e 61 6d 65 00 05 63 68   ng-user- name..ch
000001A3  6f 63 6f 22 00 0d 6c 61  73 74 2d 64 6f 63 75 6d   oco"..la st-docum
000001B3  65 6e 74 00 01 01 49 00  0f 64 6f 63 75 6d 65 6e   ent...I. .documen
000001C3  74 2d 66 6f 72 6d 61 74  00 09 69 6d 61 67 65 2f   t-format ..image/
000001D3  75 72 66 44 00 0b 63 6f  6d 70 72 65 73 73 69 6f   urfD..co mpressio
000001E3  6e 00 04 67 7a 69 70 03                            n..gzip. 
000001EB  0d 0a                                              ..
```

After this header information, the transmission of the actual file begins. We first receive a packet containing the size of the following data chunk:

```
000001ED  31 30 30 30 30 0d 0a                               10000..
```

Again, `31 30 30 30 30` translates to `0x10000` which means 65536 bytes. Then, the transmission begins. We notice, that the first two bytes `1f 8b` are the magic bytes for a gzip file. This makes sense, as the operation attributes also specify `compression` to be `gzip`. Multiple packets are then transmitted, containing the first data chunk, until another instance of `0d 0a` marks the end of the chunk.

```
000001F4  1f 8b 08 00 00 00 00 00  00 03 ec d5 4d 6f 2c 49   ........ ....Mo,I
          ...
00001E24  f1 3e da d0 f0 82 ca b2  c6 18 63 8c 33 7e 19 1a   .>...... ..c.3~..
00001E34  3b 43 69 d9 62 8c 31 c6                            ;Ci.b.1. 

00001E3C  19 1f 24 5d 90 a5 13 6c  48 92 9c f3 a8 87 63 94   ..$]...l H.....c.
          ...
00003A6C  97 46 5e 74 4a 7e a7 79  d7 0f ed 5c 3f b4 8d 5c   .F^tJ~.y ...\?..\
00003A7C  2a 79 d1 05 f9 9d e6 5d                            *y.....] 

00003A84  3f 34 1d 7f a7 81 77 fd  77 fd 2c 6e f8 7f 8e 7d   ?4....w. w.,n...}
          ...
00006D54  9f 3a dc 5a 23 47 fd a7  e2 7a 22 f1 86 5a 2d fc   .:.Z#G.. .z"..Z-.
00006D64  78 71 2f d9 0c cc a3 e7                            xq/..... 

000006D6C  07 38 36 4e be 43 c3 7f  0c 7e 6f 58 3c 3d b1 de   .86N.C.. .~oX<=..
          ...
000101DC  f9 5c de ad 9d ba bc 95  77 97 34 65 88 df 51 ee   .\...... w.4e..Q.
000101EC  a1 de c0 f5 74 57 5d bd  0d 0a                     ....tW]. ..
```

Again, a packet marking the size of the next data chunk is sent, separated by `0d 0a` and followed by the chunked data, again terminated by `0d 0a`.

```
000101F6  31 30 30 30 30 0d 0a                               10000..

000101FD  a6 44 be aa ab e2 c6 e2  69 53 aa 2f b5 be 1a ef   .D...... iS./....
          ...
0001730D  32 50 3c d1 f9 41 f0 ed  45 8e 2d 9b 24 3b b3 83   2P<..A.. E.-.$;..

0001731D  1f cd 7f 4a 3f a3 4f a6  cc f9 49 f0 fd 78 2f 67   ...J?.O. ..I..x/g
          ...
0001D8DD  ef c5 57 1e f1 6e e5 c4  01 ae 8e 70 0f 0d 81 5b   ..W..n.. ...p...[

0001D8ED  07 17 44 3a 96 6f c5 37  36 4f af de 1e 5e 8f e7   ..D:.o.7 6O...^..
          ...
000201ED  76 cf 26 bf 6d ce 19 bd  bb b6 e4 27 26 d7 8e 9e   v.&.m... ...'&...
000201FD  0d 0a                                              ..
```

This then continues until the last chunk of data is transmitted. Again, a size-denoting packet is sent, followed by the data. A last packet is then sent which contains `0d 0a 30 0d 0a 0d 0a`.

```
00030208  34 32 63 0d 0a                                     42c..

0003020D  64 32 19 39 3e 1a f9 56  a0 11 cd c9 64 32 99 4c   d2.9>..V ....d2.L
          ...
0003062D  8f f8 fd 0f a8 9b a3 7b  7c 98 32 00               .......{ |.2.

00030639  0d 0a 30 0d 0a 0d 0a                               ..0....
```

This last packet is specfial as in this example, it concatenates multiple things:

- The first instance of `0d 0a` denotes the end of the previous data chunk.
- The `30 0d 0a` is an indicator which marks the end of the chunked encoding. It can be read as a size-indicator of `30` translating to `0x00` (so zero bytes) of HTTP footer data and `0d 0a` to mark the end of the HTTP footer.
- The final `0d 0a` marks the end of the transmission. 

## How the Parser Works

In this section, I want to give a brief overview on how the IPP parser works. This should be understood as a guideline to better understand the source code but by no means replaces following the code directly. The following annotated "main" function of the ipp.py file gives a good overview over the steps undertaken to convert the network traffic into a usable printjob:

```python

def extract_ipp_jobs(infile: str, outpath: str, structure: DirStructure, force: bool) -> None:

    # Extract the individual streams
    ipp_streams = get_raw_jobs(infile)
    
    # Create desired output directory structure and write the streams to pcap files
    output.create_output_substructure(outpath, structure, force, len(ipp_streams))
    output.write_raw_streams(ipp_streams, outpath, structure)

    for i, stream in enumerate(ipp_streams):
        
        # Group the stream into header packets and the actual print job
        meta_packets, job_packets = group_ipp_packets(stream)

        # Write the meta information into a JSON file
        output.write_json(extract_meta_data(meta_packets), outpath, structure, i)
        
        # Extract the raw TCP payload (i.e. the gzipped URF file) and save the payload
        raw_payload = extract_raw_job(job_packets)
        raw_path = output.write_raw_file(raw_payload, outpath, structure, i)
        
        # Convert the URF file to a PPM file
        job_path = pwg2ppm(raw_path, outpath, structure, i)

```

We will not go into detail on how the results get saved, as this is very specific to the decision, that one should be able to group the output by job or by file-type. Thus, we simply skip the concerning functions in the following analysis.

#### `get_raw_jobs`

The function `get_raw_jobs` essentially reads in the whole pcap file supplied to the program and searches for indicator bytes. It analyses the first four bytes of each packet and checks if these are `50 4f 53 54` - the ASCII code for `POST`. If the packet is indeed a POST request, we check whether bytes two to four of the next packet symbolise an IPP `Create-Job` packet. If not, we start anew. However, if it is a `Create-Job` packet, we start dumping the following packets into a list, until the end of transmission sequence `0d 0a 30 0d 0a 0d 0a` is encountered within a packet.

> [!NOTE]
> Due to a lack of testing data, it is not clear to me, whether it would be enought to only check for an occurence of `0d 0a 0d 0a` i.e the end of the HTTP footer followed by the end of transmission indicator. Especially, if the HTTP footer is not empty, we would not have `30` but a different data size indicator and then the actual data before the final `0d 0a 0d 0a` block.

The function then returns a list, where each sublist corresponds to one such stream.

#### `group_ipp_packets`

This function takes a single stream and waits for a packet which has the payload `0d 0a`. A single packet like this is sent before the file transmission begins, indicating the end of the metadata transmission. All packets before this indicator packet are stored in one list. All packets following the indicator packet, including the indicator packet itself, get stored to a second list. These two lists are then returned.

Following the patterns identified for IPP 2.0, the `extract_meta_data` function takes the first list and parses the metadata from the POST request, the `Create-Job` and the `Send-Document` packets and writes all this information into a JSON file. The second list is handed to `extract_raw_job`. This function concatenates all packets and then uses the fact, that we always have a packet indicating the size of the following data chunk. Hence, it is fairly straightforward to separate the data from the data size indicators. However, one has to keep in mind that the chunks are separated by `0d 0a`, which leads to the `+2` occuring at various places in the code. The raw data is then also written to a binary file and finally processed using the [pwg2ppm](https://github.com/attah/ppm2pwg) program.

## Ressources

- [RFC2911 (IPP/1.1)](https://datatracker.ietf.org/doc/html/rfc2911)
- [RFC 8010 (IPP/1.1)](https://datatracker.ietf.org/doc/html/rfc8011)
- [PWG 5100.12-2015 (IPP 2.0,2.1,2.2)](https://ftp.pwg.org/pub/pwg/standards/std-ipp20-20151030-5100.12.pdf)
