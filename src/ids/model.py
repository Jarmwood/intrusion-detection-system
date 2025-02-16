from sklearn.ensemble import IsolationForest
import pandas as pd

class Model:

    def train_isolation_forest(self, df: pd.DataFrame) -> IsolationForest:
        """ Train an Isolation Forest model using the packet data. """
        model = IsolationForest(contamination=0.1)
        model.fit(df[['len']])
        return model
