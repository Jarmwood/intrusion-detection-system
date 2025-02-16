from src.ids.preprocessing import preprocess_data
from src.ids.detection import train_model, predict
from scapy.all import sniff
import pandas as pd

def main():
    # Capture packets for 60 seconds
    packets = sniff(timeout=60, filter="ip")  # Only capture IP packets

    # Preprocess captured packets
    data = preprocess_data(packets)
    
    # Load trained model (Assume it's pre-trained and saved in a file)
    model = train_model()

    # Predict intrusion
    predictions = predict(model, data)
    print(f"Predictions: {predictions}")

if __name__ == "__main__":
    main()
