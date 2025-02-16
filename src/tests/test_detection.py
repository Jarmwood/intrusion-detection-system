from src.ids.detection import train_model, predict
from sklearn.ensemble import IsolationForest
import pandas as pd

def test_train_model():
    model = train_model()
    assert isinstance(model, IsolationForest)

def test_predict():
    model = train_model()
    data = pd.DataFrame({
        "ip_src": ["192.168.1.1"],
        "ip_dst": ["192.168.1.2"],
        "protocol": [17], 
        "port_src": [12345],
        "port_dst": [80]
    })
    preds = predict(model, data)
    assert preds.shape == (1,)
    assert preds[0] in [-1, 1]  # Isolation Forest gives either -1 (outlier) or 1 (inlier)
