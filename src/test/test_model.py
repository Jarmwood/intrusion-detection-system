from src.main.model import train_isolation_forest
import pandas as pd

def test_train_isolation_forest():
    df = pd.DataFrame({'len': [100, 200, 300, 400, 500]})
    model = train_isolation_forest(df)
    assert model is not None
