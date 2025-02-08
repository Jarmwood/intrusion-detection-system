from sklearn.ensemble import IsolationForest
import pandas as pd
import joblib

def train_model():
    # Dummy data for the sake of training an Isolation Forest model.
    data = pd.DataFrame({
        "ip_src": [1, 2, 3, 4],
        "ip_dst": [5, 6, 7, 8],
        "protocol": [17, 6, 17, 6],  # 17 = UDP, 6 = TCP
        "port_src": [80, 443, 53, 22],
        "port_dst": [8080, 8443, 53, 22]
    })
    model = IsolationForest(n_estimators=100)
    model.fit(data)
    
    # Save the model for later use
    joblib.dump(model, 'model.pkl')
    return model

def predict(model, data):
    # Predict using the model
    return model.predict(data)
