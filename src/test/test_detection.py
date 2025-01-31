from src.main.detection import detect_intrusions
from sklearn.ensemble import IsolationForest
import pandas as pd

def test_detect_intrusions():
    df = pd.DataFrame({'len': [100, 200, 300, 400, 500]})
    model = IsolationForest()
    model.fit(df[['len']])
    result = detect_intrusions(model, df)
    assert 'anomaly' in result.columns
    assert result['anomaly'].iloc[0] in ['normal', 'anomalous']
