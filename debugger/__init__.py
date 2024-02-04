import signal
import sys
from multiprocessing import Event, Process

from scapy.all import UDP, sniff

from debugger.utils.actions import Actions
from debugger.utils.photon_packet_parser import PhotonPacketParser


class Sniffer:
    def __init__(self) -> None:
        self.parser = PhotonPacketParser(
            Actions.on_event, Actions.on_request, Actions.on_response
        )

        signal.signal(signal.SIGINT, self.handle_exit)

    def start_sniffing(self):
        try:
            sniff(
                prn=self.packet_callback,
                filter="udp and (port 5056 or port 5055)",
                store=0,
            )
        except Exception as e:
            pass

    def packet_callback(self, packet):
        if UDP in packet:
            udp_payload = bytes(packet[UDP].payload)

            try:
                self.parser.handle_payload(udp_payload)
            except Exception as e:
                pass

    def handle_exit(self, signum, frame):
        self.stop()
        sys.exit(0)

    def start(self):
        self.stop_sniffing = Event()
        self.sniffing_process = Process(target=self.start_sniffing)
        self.sniffing_process.start()

    def stop(self):
        self.stop_sniffing.set()

        if self.sniffing_process.is_alive():
            self.sniffing_process.terminate()

        self.sniffing_process.join()


def main():
    sniff = Sniffer()
    sniff.start()
