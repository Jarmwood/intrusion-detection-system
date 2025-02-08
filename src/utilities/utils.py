import logging

def setup_logger() -> logging.Logger:
    """
    Set up a logger for the application.
    """
    logger = logging.getLogger('intrusion_detection')
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(handler)
    return logger

def extract_ip_features(packet):
    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    return ip_src, ip_dst
