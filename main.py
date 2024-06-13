import os
import struct
from PIL import Image
from scapy.all import TCP, Packet, Raw, rdpcap, wrpcap



def setup_directory_structure(
    cwd: str,
    outdir: str,
    ipp: bool = True,
    meta: bool = True,
    zipped_hex: bool = True,
    unzipped_hex: bool = True,
) -> list[str]:
    """Sets up the directory structure for the output files."""
    directories = [outdir]
    if ipp:
        directories.append(f"{outdir}/ipp_packets")
    if meta:
        directories.append(f"{outdir}/metadata")
    if zipped_hex:
        directories.append(f"{outdir}/zipped_hex")
    if unzipped_hex:
        directories.append(f"{outdir}/unzipped_hex")
    directories.append(f"{outdir}/images")

    for dir in directories:
        if not os.path.exists(os.path.join(cwd, dir)):
            os.mkdir(dir)
    return [os.path.join(cwd, dir) for dir in directories]


def dict_to_json(data: dict[str, str], filepath: str) -> None:
    import json

    with open(filepath, "w") as file:
        json.dump(data, file)


def extract_document_transmissions(pcap_file: str, outdir: str) -> list[list[Packet]]:
    """Extracts the relevant TCP/ipp packets from the pcap file."""

    # Read the pcap file
    packets = rdpcap(pcap_file)

    # Identifiers
    post_request_identifier = "Transfer-Encoding".encode()
    end_of_transmission_identifier = bytes.fromhex("0d0a300d0a0d0a")

    grouped_packets = []
    current_group = []
    recording = False

    # Extract the traffic from initial post request to the end-of-transmission packet for each document
    for pkt in packets:
        # Filter out all ipp packets which contain a TCP payload
        if TCP in pkt and (pkt[TCP].dport == 631 and pkt[TCP].payload):
            # Identify the start of a document transmission by searching for "Transfer-Encoding" in the POST Requests
            if not recording and post_request_identifier in pkt[Raw].load:
                recording = True
                current_group = [pkt]
            # Add all following packets to the same list...
            elif recording:
                current_group.append(pkt)
                # ...until a packet containing 0d 0a 30 0d 0a 0d 0a occurs (this indicates end of transmission)
                if end_of_transmission_identifier in pkt[Raw].load:
                    grouped_packets.append(current_group)
                    recording = False
                    current_group = []

    for i, transmission in enumerate(grouped_packets):
        wrpcap(os.path.join(outdir, f"document{i+1}"), transmission)

    # TODO: Do we want to return the grouped packets or read each of them from the files generated?
    return grouped_packets


def group_ipp_packets(transmission: list[Packet]) -> tuple[list[Packet], list[Packet]]:
    """Groups the transmission into POST-Header and the document."""
    post_request_packets = transmission[:2]
    document_packets = []
    for i, pkt in enumerate(transmission[2:]):
        if bytes.fromhex("1f8b") == pkt[Raw].load[:2]:
            document_packets = transmission[2 + i : -1]
            break
    return (post_request_packets, document_packets)


def extract_post_info(pkts: list[Packet]) -> dict[str, str]:
    """Extracts the meta data from the POST request"""

    def extract_first_packet(pkt: Packet) -> dict[str, str]:
        """Extracts the meta info from the POST request."""
        results = {}
        data = pkt[Raw].load.split(b"\r\n")
        results["HTTP-request"] = data[0].decode("utf-8")
        for pair in data[1:]:
            if pair:
                key, value = pair.decode("utf-8").split(": ", 1)
                results[key] = value

        return results

    def extract_second_packet(pkt: Packet) -> dict[str, str]:
        """Extracts the attributes from the IPP request."""
        results = {}

        # Skip inital four bytes
        data = pkt[Raw].load[4:]

        # Extract IPP version
        ipp_version_major = data[0]
        ipp_version_minor = data[1]
        ipp_version = f"{ipp_version_major}.{ipp_version_minor}"
        results["ipp-version"] = ipp_version

        # Get job-ID and request-ID
        job_id, request_id = struct.unpack(">HI", data[2:8])
        results["job-id"] = job_id
        results["request-id"] = request_id

        offset = 9

        while offset < len(data) - 9:
            # Skip separator marking new key-value pair
            offset += 1

            # Extract key
            key_length = struct.unpack(">H", data[offset : offset + 2])[0]
            offset += 2
            key = data[offset : offset + key_length].decode("utf-8", errors="replace")
            offset += key_length

            # Extract value
            value_length = struct.unpack(">H", data[offset : offset + 2])[0]
            offset += 2
            value = data[offset : offset + value_length]

            if key == "job-id":
                # Unpack as 32-bit unsigned integer
                value = struct.unpack(">I", value)[0]
            elif key == "last-document":
                # Unpack as 8-bit unsigned integer as convert to boolean
                value = bool(struct.unpack(">B", value)[0])
            else:
                value = value.decode("utf-8", errors="replace")

            offset += value_length
            results[key] = value

        return results

    assert (
        len(pkts) == 2
    ), f"Length of POST request packets is not equal to two:\n{pkts[Raw].load=}"

    first_part = extract_first_packet(pkts[0])
    second_part = extract_second_packet(pkts[1])
    return {**first_part, **second_part}


def extract_document(pkts: list[Packet], outfile: str) -> None:
    """Extracts the gzipped document from the binary ipp packet dump and writes the unzipped content to a file ."""
    import gzip
    import io

    data = b''
    for pkt in pkts:
        data += pkt[Raw].load

    with gzip.open(io.BytesIO(data), 'rb') as f_in:
        decompressed = f_in.read()

    with open(outfile, 'wb') as f_out:
        f_out.write(decompressed)



def reassemble_document():
    """Reassembles the document."""
    pass


if __name__ == "__main__":
    cwd = os.getcwd()
    # TODO: Add a flag to define the output directory name
    outdir_name = "out"
    # TODO: Add flags to define if we want the ipp streams and hex of files (zipped/unzipped)
    ipp_wanted = True
    meta_wanted = True
    zipped_hex_wanted = True
    unzipped_hex_wanted = True

    # TODO: Add a flag to define the input file (or list)
    # filename = "linux2.pcap"
    filename = "linux2.pcap"
    pcap = os.path.join(cwd, filename)
    outdirs = setup_directory_structure(
        cwd,
        outdir_name,
        ipp_wanted,
        meta_wanted,
        zipped_hex_wanted,
        unzipped_hex_wanted,
    )

    outpath = os.path.join(cwd, outdir_name)

    # Filter the pcap file for document transmissions
    transmissions = extract_document_transmissions(pcap, outdirs[1])

    # Split each transmission into header and document parts
    for i, transmission in enumerate(transmissions):
        post_packets, document_packets = group_ipp_packets(transmission)

        # Extract meta information
        meta_info = extract_post_info(post_packets)
        dict_to_json(
            meta_info,
            os.path.join(outpath, "metadata", f"document{i}_meta.json"),
        )

        # Parse the print-job itself
        hexpath = os.path.join(outpath, "unzipped_hex", f"document{i}_unzip.hex")
        extract_document(document_packets, hexpath)
        rgb_matrix = hex_to_rgb(hexpath)
        
        image = Image.fromarray(rgb_matrix).convert('RGB')
        image.save('image.jpg')



"""
    [ ] Watch out with slicing:
        - Maybe we are cutting last frame of document?
        - Maybe we are including wrong frames (ipp send-document frame in document2.pcap?)
        - Are there packets which indicate the end of a page? 42c\n\r\n in document1.pcap
    [ ] What do we do with the header data?
"""
