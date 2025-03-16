import pandas as pd
import numpy as np
import pyarrow.parquet as pq
from sklearn.model_selection import train_test_split, StratifiedKFold, GridSearchCV
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score, accuracy_score, roc_auc_score, make_scorer
from joblib import dump
from tqdm import tqdm
import os
import datetime
from imblearn.over_sampling import ADASYN
from myFunc import ALGORITHMS, FEATURE_TYPES, zeroVarRead, zeroVarWrite, getDSName, log, ID_FEATURES, ALL_ID

# Paths
combined_file = './dataset/final/combined_dataset.parquet'
processed_file = './dataset/final/processed_dataset.parquet'
scaler_file = './models/scaler.joblib'
results_file = './supportFiles/dissertation/fscore_b_combined.csv'
models_dir = './models'

# Clean and process data
def clean_and_process_data():
    print('Loading combined dataset...')
    df = pd.read_parquet(combined_file)

    # Ensure all necessary columns are present
    for col in ALL_ID:
        if col not in df.columns:
            df[col] = np.nan

    #----------------#
    # Drop bad flows #
    #----------------#
    
    flowCount = df.shape[0]
    print("Flow count: {0}".format(flowCount))
    
    # Drop full NaN lines
    df.drop(df[df.isna().all(axis=1)].index, axis=0, inplace=True)
    log("combined_dataset", "Removed {0} lines of full NaN values".format(flowCount - df.shape[0]))
    flowCount = df.shape[0]
    print("Flow count: {0}".format(flowCount))
    
    # Drop ID NaN lines
    df.drop(df[df[ALL_ID].isna().any(axis=1)].index, axis=0, inplace=True)
    log("combined_dataset", "Removed {0} lines of NaN ID values".format(flowCount - df.shape[0]))
    flowCount = df.shape[0]
    print("Flow count: {0}".format(flowCount))
    
    # Drop infinity valued feature lines
    df.drop(df[(df == np.inf).any(axis=1)].index, axis=0, inplace=True)
    log("combined_dataset", "Removed {0} lines with infinity valued features".format(flowCount - df.shape[0]))
    flowCount = df.shape[0]
    print("Flow count: {0}".format(flowCount))
    
    # Drop duplicated lines
    df.drop(df[df.duplicated()].index, axis=0, inplace=True)
    log("combined_dataset", "Removed {0} duplicated lines".format(flowCount - df.shape[0]))
    flowCount = df.shape[0]
    print("Flow count: {0}".format(flowCount))
    
    df.fillna(0, inplace=True)
    
    df["dst_port"] = df["dst_port"].apply(float)
    df = df.astype({"dst_port": "int32"})
    
    df = df.astype(FEATURE_TYPES)
    columnName = 'Label'
    columnValue = 'benign'
    examples_bonafide = df[df[columnName].apply(lambda x: True if x.casefold() == columnValue else False)].shape[0]
    total = df.shape[0]
    log("combined_dataset", 'Total examples of {0} with {1} attacks and {2} bonafide flows'.format(total, total - examples_bonafide, examples_bonafide))

    # Check features with zero variance (not useful for learning) and general ID features
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    zeroVar = numeric_cols[(df[numeric_cols].var() == 0).values]
    zeroVar = np.concatenate((zeroVar.values.T, ID_FEATURES))
    zeroVarWrite(zeroVar, 0)

    # Drop zero variance features
    df.drop(columns=zeroVar, axis=1, inplace=True)

    # Save cleaned dataset
    df.to_parquet(processed_file, engine='pyarrow', index=False, compression='snappy')
    print(f'Cleaned dataset saved to {processed_file}')

# Process data in chunks
def process_data_in_chunks():
    print('Initializing StandardScaler...')
    scaler = StandardScaler()

    # First pass: fit scaler incrementally
    print('Fitting scaler incrementally...')
    parquet_file = pq.ParquetFile(processed_file)
    for batch in tqdm(parquet_file.iter_batches(batch_size=50000), desc="Fitting scaler"):
        chunk = batch.to_pandas()
        # Select only numeric columns for scaling
        numeric_cols = chunk.select_dtypes(include=[np.number]).columns
        X_chunk = chunk[numeric_cols].astype(np.float32)
        scaler.partial_fit(X_chunk)

    dump(scaler, scaler_file)
    print(f'Scaler saved to {scaler_file}')

    # Second pass: transform and save incrementally
    print('Transforming and saving data incrementally...')
    if os.path.exists(processed_file):
        os.remove(processed_file)

    for batch in tqdm(parquet_file.iter_batches(batch_size=50000), desc="Transforming data"):
        chunk = batch.to_pandas()
        # Select only numeric columns for scaling
        numeric_cols = chunk.select_dtypes(include=[np.number]).columns
        X_chunk = scaler.transform(chunk[numeric_cols].astype(np.float32))
        y_chunk = chunk['Label']
        processed_chunk = pd.DataFrame(X_chunk, columns=numeric_cols)
        processed_chunk['Label'] = y_chunk.values

        processed_chunk.to_parquet(processed_file, engine='pyarrow', index=False, compression='snappy', append=True)

    print(f'Processed dataset saved to {processed_file}')


def train_and_evaluate():
    print('Loading processed dataset...')
    df = pd.read_parquet(processed_file)
    X = df.drop(columns=['Label'])
    y = df['Label']

    print('Splitting data...')
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Oversampling minority class
    print("Oversampling minority class")
    ada = ADASYN()
    print('Original dataset shape {0}'.format(y_train.value_counts()))
    X_train, y_train = ada.fit_resample(X_train, y_train)
    print('Resampled dataset shape {0}'.format(y_train.value_counts()))

    # Standardize the features
    print('Standardizing features...')
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    # Save the scaler
    scaler_file = './models/scaler.joblib'
    dump(scaler, scaler_file)
    print(f'Scaler saved to {scaler_file}')

    # Define StratifiedKFold
    gskf = StratifiedKFold(n_splits=10, shuffle=True, random_state=17)

    # Train Models
    trained_models = {}
    for name, (model, params) in tqdm(ALGORITHMS.items(), desc="Training models"):
        start_time = datetime.datetime.now()
        print(f'Training {name} at {start_time}...')
        grid_search = GridSearchCV(model, params, cv=gskf, scoring=make_scorer(f1_score, average='weighted'))
        grid_search.fit(X_train, y_train)
        trained_models[name] = grid_search.best_estimator_
        end_time = datetime.datetime.now()
        print(f'{name} trained. Time taken: {end_time - start_time}')

    # Evaluate Models
    results = []
    for name, model in tqdm(trained_models.items(), desc="Evaluating models"):
        start_time = datetime.datetime.now()
        print(f'Evaluating {name} at {start_time}...')
        y_pred = model.predict(X_test)
        f1 = f1_score(y_test, y_pred, average='weighted')
        precision = precision_score(y_test, y_pred, average='weighted')
        recall = recall_score(y_test, y_pred, average='weighted')
        accuracy = accuracy_score(y_test, y_pred)
        confusion = confusion_matrix(y_test, y_pred)
        try:
            auc_roc = roc_auc_score(y_test, model.predict_proba(X_test), multi_class='ovr')
        except AttributeError:
            auc_roc = 'N/A'

        results.append({
            'Model': name,
            'F1 Score': f1,
            'Precision': precision,
            'Recall': recall,
            'Accuracy': accuracy,
            'AUC-ROC': auc_roc,
            'Confusion Matrix': confusion
        })

        end_time = datetime.datetime.now()
        print(f'{name} evaluated. Time taken: {end_time - start_time}')

    results_df = pd.DataFrame(results)
    results_df.to_csv(results_file, index=False)
    print(f'Results saved to {results_file}')

    # Save Models
    if not os.path.exists(models_dir):
        os.makedirs(models_dir)

    for name, model in tqdm(trained_models.items(), desc="Saving models"):
        model_file = os.path.join(models_dir, f'{name}_model.joblib')
        dump(model, model_file)
        print(f'{name} model saved to {model_file}')

if __name__ == "__main__":
    # Run the cleaning, processing, and training functions
    clean_and_process_data()
    process_data_in_chunks()
    train_and_evaluate()