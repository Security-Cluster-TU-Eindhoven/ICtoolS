from log_parsers import LogParser
import os
import pyshark
from pathlib import Path
from typing import List, Dict
from protocol_structures import ENIPPacket
import logging
from datetime import datetime

class ENIPPcapParser(LogParser):

    @staticmethod
    def parse_directory(directory: Path) -> list[ENIPPacket]:
        """
        Parse all pcap/pcapng files in the given directory and return EIP packets.
        Subdirectories are not searched: main.py already hands every log directory to the parser.
        """
        logger = logging.getLogger("EipPysharkParser")
        packets: list[ENIPPacket] = []

        pcap_files = list(directory.glob("*.pcap")) + list(directory.glob("*.pcapng"))
        for pcap in sorted(pcap_files):
                packets += ENIPPcapParser.parse_pcap(pcap)
        
        return packets


    @staticmethod
    def parse_pcap(pcap_path: Path) -> list[ENIPPacket]:
        capture = pyshark.FileCapture(str(pcap_path))
        try:
            packets = ENIPPcapParser.parse_capture(capture, pcap_path)
        finally:
            capture.close()

        return packets

    @staticmethod
    def parse_capture(capture: pyshark.FileCapture, pcap_path: Path) -> list[ENIPPacket]:
        packets: list[ENIPPacket] = []

        logger = logging.getLogger("EipPysharkParser")

        for pkt in capture:
            if not getattr(pkt, "enip", None):
                continue

            src_ip = None
            dst_ip = None
            src_port = None
            dst_port = None
            timestamp = None
            session_id = None
            transport_layer = None
            request_response = None
            command = None
            session_handle = None
            status = None
            options = None
            timeout = None
            interface_handle = None
            function_specific_data = {}

            # Layer access
            ip_layer = getattr(pkt, "ip", None)
            enip_layer = getattr(pkt, "enip", None)
            cip_layer = getattr(pkt, "cip", None)
            tcp_layer = getattr(pkt, "tcp", None)
            udp_layer = getattr(pkt, "udp", None)
            cipcm_layer = getattr(pkt, "cipcm", None)

            # Get IPs from IP layer
            if ip_layer:
                src_ip = getattr(ip_layer, "src", None)
                dst_ip = getattr(ip_layer, "dst", None)
            else:
                logger.debug(f"No IP layer in packet {pkt}")
                

            # Get ports from TCP/UDP layer
            if tcp_layer:
                src_port = int(getattr(tcp_layer, "srcport", None))
                dst_port = int(getattr(tcp_layer, "dstport", None))
                transport_layer = "TCP"
                # Stream indexes restart in every capture file, so qualify them with the file name
                session_id = f"{pcap_path.name}:tcp:{getattr(tcp_layer, 'stream', None)}"
            elif udp_layer:
                src_port = int(getattr(udp_layer, "srcport", None))
                dst_port = int(getattr(udp_layer, "dstport", None))
                transport_layer = "UDP"
                session_id = f"{pcap_path.name}:udp:{getattr(udp_layer, 'stream', None)}"
            else:
                logger.debug(f"No TCP/UDP layer in packet {pkt}")

            # Get timestamp
            timestamp = getattr(pkt, "sniff_timestamp", None)

            # Get direction (Request or Response), this is also how Wireshark achieves this, ENIP does not provide any information about if it is a request or response
            if dst_port == 44818:
                request_response = "request"
            elif src_port == 44818:
                request_response = "response"
            else:
                logger.debug(f"Could not get direction for packet {pkt}")

            # Get ENIP data from ENIP layer
            # TODO: Some packets have multiple ENIP layers. If that is the case, create a new packet for each layer.
            if enip_layer:
                command = ENIPPcapParser.fix_command(getattr(enip_layer, "command", None))
                sender_context = ENIPPcapParser.fix_context(getattr(enip_layer, "context", None))
                session_handle = getattr(enip_layer, "session", None)
                status = getattr(enip_layer, "status", None)
                options = getattr(enip_layer, "options", None)
                timeout = getattr(enip_layer, "timeout", None)
                interface_handle = getattr(enip_layer, "srrd_iface", None)
            else:
                logger.debug(f"No ENIP layer in packet {pkt}")

            parsed_packet = ENIPPacket(timestamp=timestamp, 
                                       sessionId=session_id, 
                                       src_ip=src_ip, 
                                       src_port=src_port,
                                       dst_ip=dst_ip,
                                       dst_port=dst_port,
                                       request_response=request_response,
                                       transport_layer=transport_layer,
                                       command=command,
                                       sender_context=sender_context,
                                       session_handle=session_handle,
                                       status=status,
                                       options=options,
                                       timeout=timeout,
                                       interface_handle=interface_handle,
                                       function_specific_data={})
            
            parsed_packet.item_count = getattr(enip_layer, "cpf_itemcount", None)

            # Get CIP data from CIP layer
            if cip_layer:
                parsed_packet.contains_cip = True
                parsed_packet.cip_class = getattr(cip_layer, "class", None)
                parsed_packet.cip_instance = getattr(cip_layer, "instance", None)
                parsed_packet.cip_path_segment = getattr(cip_layer, "path_segment", None)
                parsed_packet.cip_service = getattr(cip_layer, "service", None)
                parsed_packet.cip_attribute = getattr(cip_layer, "attribute", None)
            
            if cipcm_layer:
                parsed_packet.function_specific_data["service"] = getattr(cipcm_layer, "cip_service", None)
                parsed_packet.function_specific_data["class"] = getattr(cipcm_layer, "cip_class", None)
                parsed_packet.function_specific_data["instance"] = getattr(cipcm_layer, "cip_instance", None)
                parsed_packet.function_specific_data["data"] = getattr(cipcm_layer, "cip_data", None)

            # Check if a packet is malformed
            if getattr(enip_layer, "malformed_cpf_item_length_mismatch", None):
                parsed_packet.is_malformed = True
            

            packets.append(parsed_packet)

        return packets


    @staticmethod
    def fix_context(context: str) -> str:
        clean_context = context.replace(":", "")
        context_int = int(clean_context, 16)
        padded_context = f"0x{context_int:016x}"
        return padded_context

    @staticmethod
    def fix_command(command: str) -> str:
        # Convert hex string to int, then back to hex (removes leading zeros)
        return hex(int(command, 16))

    def __init__(self):
        pass
