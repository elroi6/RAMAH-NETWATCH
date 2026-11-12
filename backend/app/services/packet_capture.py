import re
import shutil
import subprocess
import tempfile

from pathlib import Path

from scapy.error import Scapy_Exception
from scapy.utils import PcapReader

from app.services.packet_analyzer import analyze_packet

            
DEFAULT_CAPTURE_DURATION = 10
MAX_CAPTURE_DURATION = 60

DEFAULT_MAX_PACKETS = 100
MAX_CAPTURE_PACKETS = 1000

SNAP_LENGTH = 256


def validate_capture_options(interface, duration, max_packets):
    if (
        not isinstance(interface, str)
        or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", interface)
    ):
        raise ValueError("Invalid capture interface.")

    if (
        isinstance(duration, bool)
        or not isinstance(duration, int)
        or not 1 <= duration <= MAX_CAPTURE_DURATION
    ):
        raise ValueError("Invalid capture duration.")

    if (
        isinstance(max_packets, bool)
        or not isinstance(max_packets, int)
        or not 1 <= max_packets <= MAX_CAPTURE_PACKETS
    ):
        raise ValueError("Invalid maximum packet count.")

    return interface


def capture_packets(
    interface,
    duration=DEFAULT_CAPTURE_DURATION,
    max_packets=DEFAULT_MAX_PACKETS,
):
    interface = validate_capture_options(
        interface,
        duration,
        max_packets,
    )

    dumpcap_binary = shutil.which("dumpcap")

    if not dumpcap_binary:
        raise RuntimeError("dumpcap is not installed.")

    with tempfile.TemporaryDirectory(
        prefix="ramah-netwatch-"
    ) as temporary_directory:

        capture_path = Path(temporary_directory) / "capture.pcapng"

        command = [
            dumpcap_binary,
            "-i", interface,
            "-a", f"duration:{duration}",
            "-c", str(max_packets),
            "-s", str(SNAP_LENGTH),
            "-w", str(capture_path),
            "-q",
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=duration + 10,
                check=False,
            )

        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Packet capture timed out.") from exc

        except OSError as exc:
            raise RuntimeError("Unable to start packet capture.") from exc

        if result.returncode != 0:
            raise RuntimeError("Packet capture failed.")

        if not capture_path.is_file():
            raise RuntimeError("Packet capture output was not created.")

        packets = []

        try:
            with PcapReader(str(capture_path)) as reader:
                for packet in reader:
                    packets.append(analyze_packet(packet))

        except (OSError, Scapy_Exception, ValueError) as exc:
            raise RuntimeError("Unable to analyze captured packets.") from exc

        return {
            "interface": interface,
            "captured_packets": len(packets),
            "packets": packets,
        }
