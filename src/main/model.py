from sklearn.ensemble import IsolationForest
import pandas as pd

def train_isolation_forest(df: pd.DataFrame) -> IsolationForest:
    """
    Train an Isolation Forest model using the packet data.
    """
    model = IsolationForest(contamination=0.1)
    model.fit(df[['len']])  # Assuming 'len' column is used for anomaly detection
    return model
