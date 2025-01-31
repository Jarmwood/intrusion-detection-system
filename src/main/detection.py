from sklearn.ensemble import IsolationForest
import pandas as pd

def detect_intrusions(model: IsolationForest, df: pd.DataFrame) -> pd.DataFrame:
    """
    Detect intrusions in the given network packet data using a trained model.
    """
    df['anomaly'] = model.predict(df[['len']])
    # Map anomaly to human-readable labels: 1 for normal, -1 for anomalous
    df['anomaly'] = df['anomaly'].map({1: 'normal', -1: 'anomalous'})
    return df
