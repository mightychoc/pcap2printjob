import argparse
import os
import subprocess

from src.extractors import ipp
from src.util import output
from src.util.bodies import DirStructure


def check_requirements() -> None:
    """Checks if all required apt/git programs are installed."""

    def is_installed(program: str) -> bool:
        """Checks if a program is part of $PATH by running the `which` command.

        Args:
            program (str): Name of program to check for.

        Returns:
            bool: True if program is installed (i.e. `which` has return code 0), False otherwise.
        """
        try:
            _proc = subprocess.run(
                ["which", program],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        except subprocess.CalledProcessError:
            return False

    needed_programs = [("pwg2ppm", "git", "https://github.com/attah/ppm2pwg")]
    missing_git_programs = []
    missing_apt_programs = []
    dependencies_missing = False

    for prog, install_type, install_name in needed_programs:
        if not is_installed(prog):
            if install_type == "git":
                missing_git_programs.append(prog)
            elif install_type == "apt":
                missing_apt_programs.append(prog)

    if missing_apt_programs:
        dependencies_missing = True
        apt_list = ""
        print("You have missing dependencies:\n")
        for prog, _, install_name in missing_apt_programs:
            print(f"\t- {prog} ({install_name})")
            apt_list += install_name + " "

        print(
            f'\nRun "sudo apt install {apt_list.strip()}" to install the missing dependencies.'
        )

    if missing_git_programs:
        dependencies_missing = True
        print("You are missing programs installable via git:\n")
        for prog, _, link in missing_git_programs:
            print(f"\t- {prog} ({link})")
        print(
            "\nPlease install the missing programs or make sure that they are part of your $PATH."
        )

    if dependencies_missing:
        exit(1)


def is_directory(path: str):
    """Check if the given path is a valid directory.

    Args:
        path (str): Path to directory to check.
    """
    if not os.path.isdir(path):
        raise argparse.ArgumentTypeError(f"{path} is not a valid directory")
    return path


def is_file(path: str):
    """Check if the given directory is a valid file.

    Args:
        path (str): Path to file to check.
    """
    if not os.path.isfile(path):
        raise argparse.ArgumentTypeError(f"{path} is not a valid file.")
    return path


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    output_structure_group = parser.add_mutually_exclusive_group()
    parser.add_argument(
        "-f", "--force", help="overwrite already existing output", action="store_true"
    )
    parser.add_argument(
        "-o",
        "--output",
        type=is_directory,
        help="path to output directory",
        default=os.getcwd(),
    )
    output_structure_group.add_argument(
        "-t",
        "--by-type",
        help="sorts output by file-type instead of by print job",
        action="store_true",
    )
    parser.add_argument("file", type=is_file, help="input file (pcap, pcapng)")

    args = parser.parse_args()

    # Set by_job as default
    dir_structure = DirStructure.by_job
    if args.by_type:
        dir_structure = DirStructure.by_type

    # Ensure the output directory is a directory
    top_outpath = os.path.abspath(args.output)
    infile = os.path.abspath(args.file)

    check_requirements()

    outdir = output.create_output_dir(top_outpath)

    ipp.extract_ipp_jobs(infile, outdir, dir_structure, args.force)
