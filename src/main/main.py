from src.main.network_capture import capture_packets
from src.main.preprocessing import preprocess_data
from src.main.model import train_isolation_forest
from src.main.detection import detect_intrusions
from src.utilities.utils import setup_logger

def main():
    # Set up logger
    logger = setup_logger()

    # Step 1: Capture network traffic
    logger.info('Capturing network traffic...')
    df = capture_packets(interface='eth0', count=100)  # Adjust interface and packet count as needed

    # Step 2: Preprocess the data
    logger.info('Preprocessing the data...')
    df = preprocess_data(df)

    # Step 3: Train the model
    logger.info('Training Isolation Forest model...')
    model = train_isolation_forest(df)

    # Step 4: Detect anomalies (intrusions)
    logger.info('Detecting intrusions...')
    result_df = detect_intrusions(model, df)

    # Output results
    print(result_df)

if __name__ == '__main__':
    main()
