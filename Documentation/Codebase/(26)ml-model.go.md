Runs all three ML components. 
- `Train()` loads data, normalizes, splits, trains all three models, evaluates on test set, returns accuracy and confusion matrix. 
- `Predict()` normalizes a feature vector and runs it through all three models simultaneously, returning a combined Prediction struct.