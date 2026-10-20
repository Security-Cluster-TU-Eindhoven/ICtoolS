from interactions import Interaction
from protocol_structures.UnifiedPacket import UnifiedPacket
from config import CONFIG
from concurrent.futures import ProcessPoolExecutor, as_completed

class InteractionHandler:

    @staticmethod
    def extract_interactions_from_packets(packets: list[UnifiedPacket], interaction_timeout: float) -> list[Interaction]:
        """ Creates a list of interactions for a given set of packets assuming that the UnifiedPacket list contains a single actor/target IP pair.

        Args:
            packets: List of packets to be grouped into interactions.
            interaction_timeout: the maximum time between two packets to still be considered a single interaction.

        Returns:
            A list of Interactions.
        """
        packets.sort(key = lambda x: float(x.timestamp))
        actorIP = packets[0].src_ip if packets[0].request_response == "request" else packets[0].dst_ip # Assume that actors only do requests and targets only respond.
        targetIP = packets[0].dst_ip if packets[0].request_response == "request" else packets[0].src_ip

        interactions: list[Interaction] = []
        interactionPackets: list[UnifiedPacket] = []
        startTime = float(packets[0].timestamp)
        lastPacketTime = float(packets[0].timestamp)


        for packet in packets:
            # This interaction ended, form an interaction for packets, start new packet collection
            if float(packet.timestamp) - float(lastPacketTime) > interaction_timeout:
                interaction = Interaction(actorIP, targetIP, startTime, lastPacketTime, interactionPackets)

                if InteractionHandler.keep_interaction(interaction):
                    interactions.append(interaction)

                
                interactionPackets = []
                startTime = float(packet.timestamp)

            interactionPackets.append(packet)
            lastPacketTime = float(packet.timestamp)

        
        # add last interaction to interaction list
        interaction = Interaction(actorIP, targetIP, startTime, lastPacketTime, interactionPackets)

        if InteractionHandler.keep_interaction(interaction):
            interactions.append(interaction)

        return interactions

    @staticmethod
    def keep_interaction(interaction: Interaction) -> bool:
        """ Returns False if the interaction must be discarded because it contains packets affected by packet loss.
        """
        if not CONFIG.DISCARD_TAINTED_INTERACTIONS:
            return True

        return not any(packet.tainted for packet in interaction.packets)



    @staticmethod
    def create_interactions(packets: list[UnifiedPacket]) -> list[Interaction]:
        """ Creates the set of interactions found within the supplied packets based on CONFIG.INTERACTION_TIMEOUT
        """
        interactions: list[Interaction] = []

        # Sort packets based on their IP pair
        grouped_packets: dict[tuple[str, str], list[UnifiedPacket]] = {}
        for packet in packets:
            ip_pair = tuple(sorted([packet.src_ip, packet.dst_ip]))
            grouped_packets.setdefault(ip_pair, []).append(packet)

        # Multithreaded extraction of interactions for all ip pairs 
        executor = ProcessPoolExecutor()
        futures = [executor.submit(InteractionHandler.extract_interactions_from_packets, packets, CONFIG.INTERACTION_TIMEOUT) for _, packets in grouped_packets.items()]
        for future in as_completed(futures):
            ip_pair_interactions = future.result()
            interactions += ip_pair_interactions


        executor.shutdown()

    
        return interactions
    