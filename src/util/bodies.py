from enum import Enum


class DirStructure(Enum):
    """Enum used to define the substructure of the output directory."""

    by_job = "by_job"  # Create a subfolder for each individual job
    by_type = "by_type"  # Create a subfolder for the pcap-files, the meta-data and the converted print jobs
