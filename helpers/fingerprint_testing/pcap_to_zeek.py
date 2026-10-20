import subprocess
import argparse
from pathlib import Path
import logging
import os
import shutil

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def generate_zeek_output(input_dir: Path, output_base: Path):
    """
    Generate Zeek logs and create the corresponding output folder structure based on the input structure.
    
    Args:
        input_dir (Path): The base input directory where the PCAP files are located.
        output_base (Path): The base output directory for storing the Zeek logs.
    """
    pcap_files = list(input_dir.rglob('*.pcap')) + list(input_dir.rglob('*.pcapng'))

    if not pcap_files:
        logger.warning(f"No PCAP files found in {input_dir}")

    for pcap_file in pcap_files:
        # Create corresponding output directory structure
        relative_path = pcap_file.relative_to(input_dir)
        pcap_output_dir = output_base / relative_path.parent / pcap_file.stem

        if pcap_output_dir.exists():
            logger.info(f"Zeek logs for {pcap_file} exist already, skipping")
            continue
        else:
            pcap_output_dir.mkdir(parents=True, exist_ok=True)

            logger.info(f"Processing {pcap_file}")
            logger.info(f"Output directory: {pcap_output_dir}")

            # Generate Modbus logs using Zeek
            generate_zeek_logs(pcap_file, pcap_output_dir)

def generate_zeek_logs(pcap_file: Path, output_dir: Path):
    """
    Run Zeek on a given PCAP file and output the logs to the specified directory.
    
    Args:
        pcap_file (Path): The path to the PCAP file.
        output_dir (Path): The directory to store the Zeek logs.
    """
    # Convert paths to absolute paths
    pcap_file = pcap_file.resolve()
    output_dir = output_dir.resolve()

    # Check if the PCAP file exists before running Zeek
    if not pcap_file.exists():
        logger.error(f"File not found: {pcap_file}")
        return

    # Ensure Zeek is in the PATH
    if shutil.which('zeek') is None:
        logger.error("Zeek is not found in the PATH.")
        return

    # Command to run Zeek with ICSNPP Modbus analysis
    zeek_command = [
        'zeek', 
        '-Cr', str(pcap_file),  # Read the PCAP file
        'icsnpp-modbus', 'znpa-umas-main'        # Use the correct module path
    ]

    # Prepare the environment variables
    env = os.environ.copy()


    try:
        # Run Zeek command and capture output
        result = subprocess.run(
            zeek_command,
            cwd=output_dir,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env
        )
        # logger.info(f"Processed {pcap_file} into {output_dir}")
        # logger.debug(f"Zeek stdout: {result.stdout}")
        # logger.debug(f"Zeek stderr: {result.stderr}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error processing {pcap_file}: {e}")
        logger.error(f"Zeek stdout: {e.stdout}")
        logger.error(f"Zeek stderr: {e.stderr}")

def main():
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Convert PCAP files to Modbus logs using Zeek.")
    parser.add_argument(
        '-i', '--input-dir', 
        type=str, 
        default='pcaps_clean', 
        help='Input directory containing PCAP files. Default is pcaps_clean.'
    )
    parser.add_argument(
        '-o', '--output-dir', 
        type=str, 
        default='zeek_logs', 
        help='Output directory to store the generated Zeek logs. Default is zeek_logs.'
    )
    
    args = parser.parse_args()

    # Define input and output directories
    input_directory = Path(args.input_dir).resolve()
    output_directory = Path(args.output_dir).resolve()

    # Ensure the output directory exists
    output_directory.mkdir(parents=True, exist_ok=True)

    logger.info(f"Input directory: {input_directory}")
    logger.info(f"Output directory: {output_directory}")

    # Generate Zeek logs and create output structure
    generate_zeek_output(input_directory, output_directory)

if __name__ == "__main__":
    main()
