import json
import logging

class CONFIG(object):
    # Logging configuration
    LOGGING_LEVEL = logging.INFO
    LOGGING_FORMAT = '%(levelname)s - %(name)s - %(message)s'

    #Interaction configuration in seconds
    INTERACTION_TIMEOUT = 11

    # Discard interactions containing packets from a connection with packet loss (Zeek's conn.log missed_bytes > 0).
    # Fingerprints require complete logs, so such interactions cannot be reliably matched.
    DISCARD_TAINTED_INTERACTIONS = True
