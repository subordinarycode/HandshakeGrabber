import time
import logging
import os
import scapy.all as scapy
from queue import Queue
import threading
import argparse
import sys
import subprocess

# Set up logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s]-[%(levelname)s]-# %(message)s')
logger = logging.getLogger(__name__)


class HandshakeGrabber:
    def __init__(self, interface, max_workers=6, channel_range=None):
        self.interface = interface
        self.access_points = {}
        self.lock = threading.Lock()
        self.packet_queue = Queue()
        self.stop_event = threading.Event()
        self.max_workers = max_workers
        self.running = False
        self.worker_threads = []
        self.channel_hopper_thread = None
        self.default_timeout = 5
        
        if channel_range:
            if channel_range == "2.4GHz":
                self.channels = list(range(1, 14))
            elif channel_range == "5GHz":
                self.channels = list(range(36, 176, 4))
            else:
                self.channels = list(range(1, 14)) + list(range(36, 176, 4))
            self.channel_hopper_thread = threading.Thread(target_self.loop_wifi_channel, daemon=True)
            self.channel_hopper_thread.start()


    def change_channel(self, channel: int) -> bool:
        """
        Changes the Wi-Fi adapter's channel to the specified channel.
        """
        if not isinstance(channel, int) or channel not in self.channels:
            return False

        for attempt in range(3):  # Retry mechanism
            try:
                subprocess.run(f"iwconfig {self.interface} channel {channel}",
                               shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return True
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to change to channel {channel}: {e}")
                time.sleep(0.5)  # Wait before retrying

        return False

    def loop_wifi_channel(self) -> None:
        """
        Changes the Wi-Fi adapter's channel in a loop.
        """
        channel_iterator = itertools.cycle(self.channels)

        try:
            while self.running:
                channel = next(channel_iterator)
                changed_successful = self.change_channel(channel)

                if not changed_successful:
                    logger.error(f"Failed to change channel to: {channel}")
                    continue
                else:

                    self.current_channel = channel

                time.sleep(self.default_timeout)

                # Dynamically remove unsupported channels
                # self.remove_unsupported_channels()

        except KeyboardInterrupt:
            print()
            logger.info("Channel hopping stopped by user.")

    @staticmethod
    def check_monitor_mode(interface) -> bool:
        """
        Checks if the specified wireless interface is in monitor mode.

        Args:
            interface (str): Name of the wireless interface

        Returns:
            bool: True if interface is in monitor mode, False otherwise

        Raises:
            ValueError: If the interface name is invalid
            RuntimeError: If the interface status cannot be determined

        Note:
            This method does not require root privileges.
        """
        if not interface or not isinstance(interface, str):
            raise ValueError("Invalid interface name provided")

        try:
            # Check if the interface exists
            interface_path = f"/sys/class/net/{interface}/"
            if not os.path.exists(interface_path):
                logger.error(f"Interface {interface} does not exist.")
                return False

            # Check the type of the interface
            with open(os.path.join(interface_path, 'type'), 'r') as f:
                interface_type = f.read().strip()

            return interface_type == '803'

        except IOError as e:
            return False

    def _parse_packet(self, packet):
        """
        Parse each packet to check if it is related to Wi-Fi handshakes, access points, or probe frames.
        """

        # Check if the packet has the necessary layer to extract the SSID
        if packet.haslayer(scapy.Dot11Beacon):
            try:
                ssid = packet[scapy.Dot11Elt].info.decode()  # Extract SSID from beacon
            except UnicodeDecodeError:
                ssid = None
            bssid = packet[scapy.Dot11].addr3
            self._update_access_point(bssid, "beacon", packet, ssid)

        elif packet.haslayer(scapy.EAPOL):
            bssid = packet[scapy.Dot11].addr3

            frame_number = self.get_frame_number(packet)  # Pass the full packet
            if frame_number:
                self._update_access_point(bssid, frame_number, packet)

                self._save_to_pcap(bssid)

    def _update_access_point(self, bssid, frame_type, packet, ssid=None):
        """
        Helper function to update the access_points dictionary with time validation.
        """
        with self.lock:
            if bssid not in self.access_points:
                logger.info(f"New BSSID Found: {bssid}")
                self.access_points[bssid] = {
                    "name": "",
                    "beacon": "",
                    "eapol": {},
                }


            if isinstance(frame_type, int):
                if not frame_type in self.access_points[bssid]["eapol"]:
                    self.access_points[bssid]["eapol"][frame_type] = packet
                    logger.info(f"EAPOL packet {frame_type}/4 from {packet[scapy.Dot11].addr2}")
                else:
                    logger.info(f"EAPOL packet {frame_type}/4 already exists from {packet[scapy.Dot11].addr2}")
            else:
                self.access_points[bssid][frame_type] = packet
                self.access_points[bssid]["name"] = ssid

    def _save_to_pcap(self, bssid):
        """
        Save captured handshake packets to a .pcap file once a complete handshake is captured.
        """
        if not os.path.isdir("pcaps"):
            os.makedirs("pcaps", exist_ok=True)
        name = self.access_points[bssid]["name"]

        pcap_path = os.path.join("pcaps", f"{name}_handshake.pcap" if name else "hidden_networks_handshake.pcap")

        # if len(self.access_points[bssid]["eapol"].keys()) == 4:
        with self.lock:
            with scapy.PcapWriter(pcap_path, sync=True) as pcap_writer:
                pcap_writer.write(self.access_points[bssid]["beacon"])

                for eapol_packet in self.access_points[bssid]["eapol"].values():
                   pcap_writer.write(eapol_packet)


            logger.info(f"Saved handshake to {pcap_path} for AP with BSSID: {bssid}")

    def get_frame_number(self, packet):
        """
        Determine the EAPOL message number based on the packet flags.
        """
        if packet.haslayer(scapy.EAPOL_KEY):
            key_info = packet[scapy.EAPOL_KEY]

            # Frame 1: Authenticator -> Supplicant (has_key_mic=0, key_ack=1, install=0)
            if not key_info.has_key_mic and key_info.key_ack and not key_info.install:
                return 1
            return key_info.guess_key_number()

        with self.lock:
            logger.error("Unable to detect frame number for EAPOL packet.")

        return None

    def _do_work(self):
        while not self.stop_event.is_set():
            packet = self.packet_queue.get()
            self._parse_packet(packet)
            self.packet_queue.task_done()

    def _add_packet_to_queue(self, packet):
        self.packet_queue.put(packet)

    def start(self):
        if not self.running:
            self.running = True
            for i in range(self.max_workers):
                t = threading.Thread(target=self._do_work, daemon=True)
                self.worker_threads.append(t)
                t.start()

        scapy.sniff(iface=self.interface, prn=self._add_packet_to_queue, store=0, stop_filter=self._stop_sniffing)

    def _stop_sniffing(self, pkt):
        return self.stop_event.is_set()

    def stop(self):
        if self.running:
            self.running = False
            self.stop_event.set()
            for t in self.worker_threads:
                if t.is_alive():
                    t.join(0.5)

            self.worker_threads = []


def main():
    # Check if the script is being run as root
    if os.geteuid() != 0:
        logger.error("This script must be run as root (use sudo).")
        sys.exit(1)  # Exit the program with an error code

    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description="Wi-Fi Handshake Sniffer")
    parser.add_argument("interface", help="The network interface to use for sniffing (e.g., wlan0).")
    parser.add_argument("--max_workers", type=int, default=6, help="Number of worker threads for packet processing.")
    parser.add_argument("--channel", type=int, help="Channel to sniff on")
    parser.add_argument("--band", default=None, type=str,  help="Enable channel hopping on (Default 2.4GHZ) (Options 2.4GHz, 5GHz, all")

    args = parser.parse_args()

    # Initialize the HandshakeGrabber
    grabber = HandshakeGrabber(
        interface=args.interface,
        max_workers=args.max_workers,
        channel_range=args.band
    )

    if not grabber.check_monitor_mode():
        logger.error(f"Interface {args.interface} does not appear to be in monitor mode.")
        exit(1l)

    if args.channel:
        grabber.change_channel(args.channel)

    # Start sniffing in a separate thread
    try:
        logger.info("Starting the handshake sniffer...")
        threading.Thread(target=grabber.start, daemon=True).start()
        while grabber.running:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Stopping the sniffer due to keyboard interrupt...")
        grabber.stop()


if __name__ == "__main__":
    main()

