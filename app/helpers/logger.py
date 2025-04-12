from datetime import datetime
import logging

logging.basicConfig(filename="audit.log", level=logging.INFO, format='%(asctime)s - %(message)s')

def log_event(event_type: str, username: str, message: str = ""):
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"{timestamp} | {event_type} | {username} | {message}"
    logging.info(log_message)