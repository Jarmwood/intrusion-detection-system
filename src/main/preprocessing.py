from sklearn.preprocessing import StandardScaler
import pandas as pd

def preprocess_data(df: pd.DataFrame) -> pd.DataFrame:
    """
    Preprocess the captured packet data for ML model.
    """
    scaler = StandardScaler()
    df['len'] = scaler.fit_transform(df[['len']])
    return df
