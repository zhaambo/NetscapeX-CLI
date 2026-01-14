"""Dummy ML traffic classifier using scikit-learn RandomForest.

If a model file is not present, trains a small random model and saves it.
"""
import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier


class MLClassifier:
    def __init__(self, model_path='model.pkl'):
        self.model_path = model_path
        self.model = None
        self.feature_cols = ['pkt_count', 'duration', 'iat_mean', 'iat_var', 'pkt_size_mean', 'pkt_size_var', 'burst_count']
        self._ensure_model()

    def _ensure_model(self):
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
            except Exception:
                self.model = None

        if self.model is None:
            # Train a dummy model on random data
            X = np.random.rand(200, len(self.feature_cols))
            y = (np.random.rand(200) > 0.7).astype(int)
            clf = RandomForestClassifier(n_estimators=20, random_state=42)
            clf.fit(X, y)
            self.model = clf
            try:
                joblib.dump(clf, self.model_path)
            except Exception:
                pass

    def predict_proba(self, df):
        # Expect a pandas DataFrame
        try:
            X = df[self.feature_cols].fillna(0).values
        except Exception:
            # fallback: try to construct columns
            X = []
            for _, row in df.iterrows():
                X.append([row.get(c, 0) for c in self.feature_cols])
            import numpy as _np
            X = _np.array(X)

        probs = self.model.predict_proba(X)[:, 1]
        return probs
