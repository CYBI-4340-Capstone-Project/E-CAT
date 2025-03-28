import pandas as pd
import joblib

def load_models(model_dir):
    """
    Loads all models from the specified directory.
    """
    import os
    models = {}
    for model_file in os.listdir(model_dir):
        if model_file.endswith('.joblib'):
            model_name = model_file.replace('.joblib', '')
            models[model_name] = joblib.load(os.path.join(model_dir, model_file))
    return models

def predict(models, data_csv):
    """
    Predicts intrusions using the loaded models and returns the results.
    """
    df = pd.read_csv(data_csv)
    predictions = {}
    for model_name, model in models.items():
        predictions[model_name] = model.predict(df)
    return predictions

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run intrusion detection on preprocessed data.")
    parser.add_argument("-m", "--models", required=True, help="Directory containing trained models")
    parser.add_argument("-d", "--data", required=True, help="Preprocessed data CSV file")
    args = parser.parse_args()

    models = load_models(args.models)
    predictions = predict(models, args.data)
    for model_name, preds in predictions.items():
        print(f"Model: {model_name}, Predictions: {preds}")
