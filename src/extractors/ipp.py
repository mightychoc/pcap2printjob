import os
import struct
import subprocess

from scapy.all import TCP, Packet, Raw, rdpcap, wrpcap
from src.util import output
from src.util.bodies import DirStructure


def get_raw_jobs(pcapfile: str) -> list[list[Packet]]:
    """Extracts the individual IPP streams from the network capture.

    Args:
        pcapfile (str): Packet capture file containing the print jobs

    Returns:
        list[list[Packet]]: A list containing the individual TCP streams of each print job
    """

    def is_create_job_packet(pkt: Packet) -> bool:
        """Checks if the packet following a POST-Request is an IPP Create-Job packet.

        Args:
            pkt (Packet): Packet to check

        Returns:
            bool: True if it is a Create-Job packet, False otherwise
        """

        return pkt[Raw].load[2:4] == b"\x00\x05"

    def is_eot_packet(pkt: Packet) -> bool:
        """Checks if the packet contains the End-Of-Transmission identifier.

        Args:
            pkt (Packet): Packet to check

        Returns:
            bool: True if EOT identifier is in packet, False otherwise
        """

        # NOTE: It might be enough to only look for 0x0d0a0d0a as onle EOT packet should have
        # this structure. Specifically, we have a 0x0d0a for the end of the footer followed
        # by another one for the end of transmission.
        # Looking for 0x0d0a300d0a0d0a might be problematic if there is footer data (meaning
        # we do not have 30 but another identifier for the footer length).
        return b"\x0d\x0a\x30\x0d\x0a\x0d\x0a" in pkt[Raw].load

    data = rdpcap(pcapfile)

    grouped_packets = []
    current_group = []
    state = "WAIT_POST"

    for pkt in data:
        # Filter for IPP packets which actually contain data
        if TCP in pkt and (pkt[TCP].dport == 631 and pkt[TCP].payload):
            # grouped_packets.append(pkt[Raw])

            if state == "WAIT_POST":
                if pkt[Raw].load[:4] == b"POST":
                    state = "WAIT_CREATE_JOB"
                    current_group = [pkt]

            elif state == "WAIT_CREATE_JOB":
                if is_create_job_packet(pkt):
                    state = "WAIT_EOT"
                    current_group.append(pkt)
                else:
                    state = "WAIT_POST"
                    current_group = []

            elif state == "WAIT_EOT":
                current_group.append(pkt)
                if is_eot_packet(pkt):
                    grouped_packets.append(current_group)
                    state = "WAIT_POST"
                    current_group = []

    return grouped_packets


def group_ipp_packets(stream: list[Packet]) -> tuple[list[Packet], list[Packet]]:
    """Groups the TCP stream of a print job into packets containing metadata and packets containing the actual job.

    Args:
        stream (list[Packet]): TCP stream of the print job.

    Returns:
        tuple[list[Packet], list[Packet]]: Tuple of the form (Metadata-packets, Job-packets)
    """

    meta_packets = []
    job_packets = []
    meta_packets_finished = False

    for pkt in stream:
        if not meta_packets_finished:
            # Identify the end-of-chunk packet (\r\n) from the Send-Document stream
            if pkt[Raw].load == b"\x0d\x0a":
                meta_packets_finished = True
                job_packets.append(pkt)
            else:
                meta_packets.append(pkt)
        else:
            job_packets.append(pkt)

    return (meta_packets, job_packets)


def extract_meta_data(
    packets: list[Packet],
) -> dict[str, dict[str, dict[str, str | bool | int]]]:

    def extract_post_info(pkt: Packet) -> dict[str, str]:
        """Extracts the key-value pairs from a POST-request.

        Args:
            packet (Packet): The POST-request.

        Returns:
            dict[str, str]: Parsed POST-request attributes.
        """
        post_info = {}
        data = pkt[Raw].load.split(b"\x0d\x0a")
        post_info["request"] = data[0].decode("utf-8")
        for pair in data[1:]:
            if pair:
                key, value = pair.decode("utf-8").split(": ")
                post_info[key] = value
        return post_info

    def extract_create_job_info(pkt: Packet) -> dict[str, str | int]:
        """Extracts the key-value pairs from a create-job request.

        TODO: At the moment, we only extract the operation-attributes and not the job-attributes!

        Args:
            pkt (Packet): The create-job request.

        Returns:
            dict[str, str | int]: Parsed create-job attributes.
        """
        # TODO: Add a parsing logic for the job-attributes media struct
        attr_info = {}
        data = pkt[Raw].load

        # Parse the IPP version
        version_major = data[0]
        version_minor = data[1]
        attr_info["ipp-version"] = f"{version_major}.{version_minor}"

        # Parse operation-id and request-id
        operation_id, request_id = struct.unpack(">HI", data[2:8])
        attr_info["operation-id"] = operation_id
        attr_info["request-id"] = request_id

        offset = 9
        is_operations_attribute = True

        while offset < len(data) - 9:
            # Do not extract the job-attributes
            delimiter = data[offset]
            if delimiter == 2:
                break

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
                # Interpret as uint32
                value = struct.unpack(">I", value)[0]
            elif key == "last-document":
                # Interpret as boolean
                value = bool(struct.unpack(">B", value))[0]
            else:
                value = value.decode("utf-8", errors="replace")

            offset += value_length
            attr_info[key] = value

        return attr_info

    def extract_send_document_info(pkt: Packet) -> dict[str, str | bool | int]:
        """Extracts the key-value pairs from a send-document request.

        Args:
            packet (Packet): The send-document request.

        Returns:
            dict[str, str]: Parsed send-document attributes.
        """
        attr_info = {}
        data = pkt[Raw].load

        # Check if the packet starts with the version number or with the chunk size
        if data[2:4] == b"\x0d\x0a":
            data = pkt[Raw].load[4:]

        # Parse the IPP version
        version_major = data[0]
        version_minor = data[1]
        attr_info["ipp-version"] = f"{version_major}.{version_minor}"

        # Parse operation-id and request-id
        operation_id, request_id = struct.unpack(">HI", data[2:8])
        attr_info["operation-id"] = operation_id
        attr_info["request-id"] = request_id

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
                # Interpret as uint32
                value = struct.unpack(">I", value)[0]
            elif key == "last-document":
                # Interpret as boolean
                value = bool(struct.unpack(">B", value)[0])
            else:
                value = value.decode("utf-8", errors="replace")

            offset += value_length
            attr_info[key] = value

        return attr_info

    assert (
        len(packets) == 4
    ), f"There are not exactly four meta-packets! Please check, if group_ipp_packets works correctly.\nPackets:\n{packets}."
    create_job_dict = {
        "post-request": extract_post_info(packets[0]),
        "attributes": extract_create_job_info(packets[1]),
    }
    send_document_dict = {
        "post-request": extract_post_info(packets[2]),
        "attributes": extract_send_document_info(packets[3]),
    }

    return {"create-job": create_job_dict, "send-document": send_document_dict}


def extract_raw_job(pkts: list[Packet]) -> None:

    def reassemble_job(pkts: list[Packet]) -> bytes:
        """Extracts the raw data chunks from the TCP stream.

        Args:
            pkts (list[Packet]): Packets in the TCP stream after the Meta-Packets (i.e. job_packets returned by group_ipp_packets()).

        Returns:
            bytes: Reassembled data blob.
        """

        data = b""
        # First packet is always end-of-chunk packet from the headers. Hence we ignore it.
        for pkt in pkts[1:]:
            data += pkt[Raw].load

        data_chunks = []
        index = 0
        data_length = len(data)

        # The second packet denotes the length of the following data chunk.
        # Hence we extract and convert the next packet, extract as many bytes as denoted by it and
        # repeat this, until end-of-transmission is reached
        while index < data_length:

            # Find the next instance of \r\n which denotes end of size header
            delimiter_index = data[index:].find(b"\x0d\x0a")

            # If we reached the last size header, break
            if delimiter_index == -1:
                break

            # Extract length of following data block
            size_part = data[index : index + delimiter_index]
            number_of_data_bytes = int(size_part, 16)

            # Advance index past the delimiter
            index += delimiter_index + 2

            # Extract the data chunk
            data_chunks.append(data[index : index + number_of_data_bytes])

            # Advance index past the data chunk
            index += number_of_data_bytes + 2

        transmitted_file = b""
        # The end-of-transmission packet ends in 0x0d0a300d0a0d0a. Thus our parser generates a last empty packet.
        # TODO: If this is not 0 we would have a footer - but so far I have not seen one, so I cannot tell you how this would behave...
        for chnk in data_chunks:
            if chnk:
                transmitted_file += chnk

        return transmitted_file

    def decompress(file: bytes) -> bytes:
        """Decompressed the transmitted file

        Args:
            file (bytes): Byte stream of the compressed file.

        Returns:
            bytes: Byte stream of the decompressed file.
        """
        if file[:2] == b"\x1f\x8b":
            import gzip

            raw = gzip.decompress(file)
            return raw

        # Allows for other file types by extending with similar magic byte identifiers

        print(
            "WARNING: Could not decompress the payload! Returning original file contents."
        )
        return file

    transmitted_file = reassemble_job(pkts)
    raw_payload = decompress(transmitted_file)
    return raw_payload


def pwg2ppm(
    filepath: str, outpath: str, structure: DirStructure, stream_number=0
) -> str:
    """Converts an urf/UNIRAST file to a ppm file.

    Args:
        filepath (str): Path to urf/UNIRAST file.
        outpath (str): Path to output directory.
        structure (DirStructure): Substructure of the output directory.
        stream_number (int, optional): Number of TCP stream to label file accordingly. Defaults to 0.

    Returns:
        str: _description_
    """
    try:
        if structure.value == DirStructure.by_job.value:
            path = os.path.join(
                outpath, f"Job{stream_number + 1}", f"Job{stream_number + 1}_"
            )
            _proc = subprocess.run(
                ["pwg2ppm", filepath, path],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            return path
        elif structure.value == DirStructure.by_type.value:
            path = os.path.join(outpath, "jobs", f"Job{stream_number + 1}_")
            _proc = subprocess.run(
                ["pwg2ppm", filepath, path],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            return path

    except subprocess.CalledProcessError as e:
        output.print_error(
            f"Could not convert {filepath} to ppm file. See the following error message for more details:"
        )
        print(e.stdout)
        exit(1)


def extract_ipp_jobs(infile: str, outpath: str, structure: DirStructure) -> None:
    """Extracts all IPP print jobs from a pcap file.

    Args:
        infile (str): Path to pcap file containing the network traffic to analyze.
        outpath (str): Path to output directory.
        structure (DirStructure): Substructure of output directory.
    """

    ipp_streams = get_raw_jobs(infile)
    output.create_output_substructure(outpath, structure, len(ipp_streams))
    output.write_raw_streams(ipp_streams, outpath, structure)

    for i, stream in enumerate(ipp_streams):
        meta_packets, job_packets = group_ipp_packets(stream)
        output.write_json(extract_meta_data(meta_packets), outpath, structure, i)
        raw_payload = extract_raw_job(job_packets)
        raw_path = output.write_raw_file(raw_payload, outpath, structure, i)
        job_path = pwg2ppm(raw_path, outpath, structure, i)
