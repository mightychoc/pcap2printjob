import os
from json import dump
from typing import Any

from scapy.all import Packet, wrpcap
from src.util.bodies import DirStructure


def print_error(msg: str) -> None:
    """Prints an error message.

    Args:
        msg (str): Message to print.
    """
    print("\033[91m[ERROR] - " + msg + "\033[0m")


def print_warning(msg: str) -> None:
    """Prints a warning message.

    Args:
        msg (str): Message to print.
    """
    print("\033[93m[WARNING] - " + msg + "\033[0m")


def check_write_permissions(path: str) -> bool:
    """Checks whether the user has write-permissions in the specified directory.

    Args:
        path (str): Path to directory to check.

    Returns:
        bool: True if user has write permissions, False otherwise.
    """
    return os.access(path, os.W_OK)


def create_output_dir(maindir: str) -> str:
    """Creates the top-level output directory.

    Args:
        maindir (str): Path to the directory to create output directory in.

    Returns:
        str: Full path of the output directory.
    """

    if check_write_permissions(maindir):
        outdir = os.path.join(maindir, "output")

        if not os.path.exists(outdir):
            os.mkdir(outdir)
        return outdir

    else:
        print_error(
            f"Could not create output directory: Write permissions denied for {maindir}"
        )
        exit(1)


def create_output_substructure(
    outdir: str, structure: DirStructure, force: bool, number_of_jobs: int = 0
) -> None:
    """Creates the substructure in the output directory. This can either be:

    - A directory per print job, each containing the pcap and the metadata of the print job as well as an image of the printed file
    - Three directories:
        - pcap files of the individual print jobs
        - Metadata files
        - Images of the converted jobs

    Args:
        outdir (str): Path to the output directory which will hold the substructure.
        structure (DirStructure): Specifies which substructure to create.
        force (bool): If True, allows overwriting existing output directories.
        number_of_streams (int, optional): Number of different print jobs extracted by get_raw_jobs(). Defaults to 0.
    """

    try:
        if structure.value == DirStructure.by_job.value:
            for i in range(number_of_jobs):
                os.mkdir(os.path.join(outdir, f"Job{i+1}"))
        elif structure.value == DirStructure.by_type.value:
            os.mkdir(os.path.join(outdir, "streams"))
            os.mkdir(os.path.join(outdir, "metadata"))
            os.mkdir(os.path.join(outdir, "raw-payloads"))
            os.mkdir(os.path.join(outdir, "jobs"))

        else:
            print_error(f"Unknown directory structure: {structure}")
            exit(1)
    except FileExistsError as e:
        if not force:
            print_error(f"Output subdirectory {e.filename} already exists!")
            print(f"Use the -f flag to allow for overwriting.")
            exit(1)
        else:
            print_warning(f"Overwriting output subdirectory {e.filename}.")


def write_raw_streams(
    streams: list[list[Packet]], outdir: str, structure: DirStructure
) -> str:
    """Generates a pcap file containing the TCP stream of each print job.

    Args:
        streams (list[list[Packet]]): List of streams extracted by get_raw_jobs() from the original pcap file.
        outdir (str): Path to output directory.
        structure (DirStructure): Substructure of output directory.

    Returns:
        str: Path to the created pcap file.
    """
    for i, stream in enumerate(streams):
        if structure.value == DirStructure.by_job.value:
            wrpcap(os.path.join(outdir, f"Job{i+1}", f"Stream{i+1}.pcap"), stream)
        elif structure.value == DirStructure.by_type.value:
            wrpcap(os.path.join(outdir, "streams", f"Stream{i+1}.pcap"), stream)


def write_json(
    data: dict[str, Any], outdir: str, structure: DirStructure, stream_number=0
) -> str:
    """Write a JSON file according to the output directory structure.

    Args:
        data (dict[str, Any]): Dictionary to dump.
        outdir (str): Path to output directory.
        structure (DirStructure): Substructure of output directory.
        stream_number (int, optional): Number of TCP stream to label file accordingly. Defaults to 0.

    Returns:
        str: Path to the created JSON file.
    """
    if structure.value == DirStructure.by_job.value:
        path = os.path.join(
            outdir, f"Job{stream_number + 1}", f"Metadata{stream_number + 1}.json"
        )
        with open(path, "w") as out:
            dump(data, out)
        return path
    elif structure.value == DirStructure.by_type.value:
        path = os.path.join(outdir, "metadata", f"Metadata{stream_number + 1}.json")
        with open(path, "w") as out:
            dump(data, out)
        return path


def write_raw_file(
    payload: bytes, outdir: str, structure: DirStructure, stream_number=0
) -> str:
    """Writes the raw data of the decompressed payload according to the output directory structure.

    Args:
        payload (bytes): Raw decompressed file.
        outdir (str): Path to output directory.
        structure (DirStructure): Substructure of the output directory.
        stream_number (int, optional): Number of TCP stream to label file accordingly. Defaults to 0.

    Returns:
        str: Path to the raw data file.
    """

    if structure.value == DirStructure.by_job.value:
        path = os.path.join(
            outdir, f"Job{stream_number + 1}", f"RawPayload{stream_number + 1}.bin"
        )
        with open(path, "wb") as out:
            out.write(payload)
        return path
    elif structure.value == DirStructure.by_type.value:
        path = os.path.join(outdir, "raw-payloads", f"RawPayload{stream_number+1}.bin")
        with open(path, "wb") as out:
            out.write(payload)
        return path
