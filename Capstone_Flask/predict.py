import os
import sys
import pandas as pd
import numpy as np
import logging
import joblib
from datetime import datetime
from pathlib import Path
from typing import Dict, Tuple
import json
from sklearn.metrics import accuracy_score, precision_score

# Configure logging
log_dir = os.path.join("logs", datetime.now().strftime('%Y-%m-%d'))
os.makedirs(log_dir, exist_ok=True)  # Ensure the directory exists

log_file = os.path.join(log_dir, datetime.now().strftime('predict.log'))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename=log_file,
    filemode='a'  # Append to the log file if it exists
)

class Predictor:
    def __init__(self, base_path=None):
        self.base_path = base_path or str(Path(__file__).parent)
        self.model_dir = os.path.join(self.base_path, "models")
        self.data_path = os.path.join(self.base_path, "Databases")
        
            # Load label mapping from training.json
        with open(os.path.join(self.base_path, "training.json"), "r") as f:
            training_config = json.load(f)
            self.label_mapping = {label: idx for idx, label in enumerate(training_config["label_values"])}
            self.inverse_mapping = {idx: label for label, idx in self.label_mapping.items()}
        
        os.makedirs(self.model_dir, exist_ok=True)

    def load_models(self) -> Dict:
        """Load all trained models from the model directory"""
        models = {}
        try:
            for model_file in os.listdir(self.model_dir):
                if model_file.endswith('.joblib'):
                    model_name = os.path.splitext(model_file)[0]
                    logging.info(f"Loading model: {model_name}")
                    model_path = os.path.join(self.model_dir, model_file)
                    models[model_name] = joblib.load(model_path)
                    logging.info(f"Loaded model: {model_name}")
            return models
        except Exception as e:
            logging.error(f"Model loading failed: {str(e)}")
            raise

    def _preprocess_for_prediction(self, df: pd.DataFrame) -> pd.DataFrame:
        """Prepare dataframe for prediction by removing non-feature columns"""
        # Columns to drop (non-feature columns)
        cols_to_drop = [
            "flow_id", "timestamp", "src_ip", "dst_ip",
            "bwd_blk_rate_avg", "bwd_byts_b_avg", "fwd_blk_rate_avg",
            "fwd_byts_b_avg", "fwd_pkts_b_avg", "bwd_pkts_b_avg", 
            "bwd_urg_flags", "fwd_urg_flags", "cwe_flag_count", 
            "ece_flag_cnt", "bwd_psh_flags", "protocol_cic", 
            "protocol_tshark", "Label" # Ensure Label column is removed
        ]
        
        # Drop columns that exist in the dataframe
        cols_to_drop = [col for col in cols_to_drop if col in df.columns]
        return df.drop(columns=cols_to_drop, errors='ignore')

    def predict(self, user_id: str, final_path: str) -> Dict:
        """
        Run prediction pipeline with error handling and default BENIGN fallback
        """
        try:
            # Load models
            models = self.load_models()
            if not models:
                raise ValueError("No models found in models directory")
            
            # Load data
            if isinstance(final_path, pd.DataFrame):
                df = final_path
            else:
                if not os.path.exists(final_path):
                    raise FileNotFoundError(f"Processed data not found: {final_path}")
                df = pd.read_csv(final_path)
            
            # Preprocess data for prediction
            predict_df = self._preprocess_for_prediction(df)
            # Prepare default results (BENIGN)
            # Create a results DataFrame structure
            results_df = pd.DataFrame({
                'flow_id': df['flow_id'] if 'flow_id' in df.columns else np.arange(len(df)),
                'timestamp': df['timestamp'] if 'timestamp' in df.columns else '',
                'src_ip': df['src_ip'] if 'src_ip' in df.columns else '',
                'dst_ip': df['dst_ip'] if 'dst_ip' in df.columns else '',
                'src_port': df['src_port'] if 'src_port' in df.columns else '',
                'dst_port': df['dst_port'] if 'dst_port' in df.columns else '',
                'protocol': df['protocol'] if 'protocol' in df.columns else ''
            })
            
            # Prepare results structure
            results = {
                'threat_type': "BENIGN",
                'accuracy': 0.0,
                'malicious_count': 0,
                'total_flows': len(df),
                'results_df': results_df,  # This will store all prediction results
                'model_details': {},  # Store model-specific stats
                'results_path': ''
            }
            
            # Make predictions
            for model_name, model in models.items():
                try:
                    # Get predictions
                    if hasattr(model, 'predict_proba'):
                        proba = model.predict_proba(predict_df)
                        preds = np.argmax(proba, axis=1)
                        print(f"Preds: {preds}")
                        confidence_scores = np.max(proba, axis=1)
                    else:
                        preds = model.predict(predict_df)
                        print(f"Preds in else: {preds}")
                        confidence_scores = np.ones(len(preds))
                    
                    # Add predictions to results DataFrame
                    results_df[f'{model_name}_prediction'] = [self.inverse_mapping.get(p, "BENIGN") for p in preds]
                    results_df[f'{model_name}_confidence'] = confidence_scores
                    
                    # Update model details
                    results['model_details'][model_name] = {
                        'accuracy': accuracy_score(results_df['true_label'], results_df[f'{model_name}_prediction']) 
                                if 'true_label' in results_df.columns else None,
                        'precision': precision_score(results_df['true_label'], results_df[f'{model_name}_prediction'], average='weighted', zero_division=0)
                                if 'true_label' in results_df.columns else None
                    }
                    
                    # Update threat detection
                    malicious_mask = results_df[f'{model_name}_prediction'] != "BENIGN"
                    if malicious_mask.any():
                        results['malicious_count'] += malicious_mask.sum()
                        most_confident = results_df[malicious_mask].nlargest(1, f'{model_name}_confidence')
                        if not most_confident.empty:
                            results['threat_type'] = most_confident[f'{model_name}_prediction'].iloc[0]
                            results['accuracy'] = most_confident[f'{model_name}_confidence'].iloc[0]
                            
                except Exception as e:
                    logging.warning(f"Prediction failed with {model_name}: {str(e)}")
                    print(f"Except for prediction: {e}")
                    continue
            
            # Add summary columns
            results_df['is_malicious'] = results_df[[f'{m}_prediction' for m in models]].apply(
                lambda x: any(p != "BENIGN" for p in x), axis=1)
            # Extract the directory and filename from final_path
            output_dir = os.path.dirname(final_path)  # Get the directory path
            file_name = os.path.basename(final_path).replace("_final.csv", "")  # Remove "_final.csv" from the filename

            # Merge predictions and confidence columns into the original DataFrame
            for model_name in models.keys():
                df[f'{model_name}_prediction'] = results_df[f'{model_name}_prediction']
                df[f'{model_name}_confidence'] = results_df[f'{model_name}_confidence']

            # Construct the new results CSV path
            output_csv_path = os.path.join(output_dir, f"{file_name}_results.csv")

            # Save the updated DataFrame to the new CSV file
            df.to_csv(output_csv_path, index=False)
            logging.info(f"Saved results DataFrame with predictions to {output_csv_path}")

            # Include the path to the saved CSV in the results
            results['results_path'] = output_csv_path
            return {
                'summary': results,
                'results_df': results_df
            }

        except Exception as e:
            logging.error(f"Prediction failed: {str(e)}")
            print(f"Prediction failed {e}")
            return {
                'summary': {
                    'threat_type': "BENIGN",
                    'accuracy': 0.0,
                    'malicious_count': 0,
                    'total_flows': len(df) if 'df' in locals() else 0,
                    'results_path': ''
                },
                'results_df': pd.DataFrame()  # Empty DataFrame on error
            }

def main():
    """Command-line interface"""
    import argparse
    parser = argparse.ArgumentParser(description="Run intrusion detection predictions")
    parser.add_argument("user_id", help="User ID")
    parser.add_argument("pcap_name", help="Path to final processed CSV")
    args = parser.parse_args()

    try:
        predictor = Predictor()
        prediction_results = predictor.predict(args.user_id, args.pcap_name)

        # Ensure we have all required fields with defaults
        summary = prediction_results.get('summary', {})
        results_df = prediction_results.get('results_df', pd.DataFrame())

        # Print summary
        print("\n=== Prediction Summary ===")
        print(f"Threat Type: {summary.get('threat_type', 'Unknown')}")
        print(f"Confidence: {summary.get('accuracy', 0.0):.2%}")
        print(f"Malicious Flows: {summary.get('malicious_count', 0)}/{summary.get('total_flows', 0)}")
        print(f"Results saved to: {summary.get('results_path', 'N/A')}")

        # Print detailed results for each flow
        print(f"{'Timestamp':<20} {'Source':<25} {'Destination':<25} {'Protocol':<10} {'XGB Prediction':<20} {'DT Prediction':<20}")
        print("=" * 120)
        for _, row in prediction_results['results_df'].iterrows():
            print(
                f"{row.get('timestamp', 'N/A'):<20} "
                f"{row.get('src_ip', 'N/A')}:{row.get('src_port', 'N/A'):<25} "
                f"{row.get('dst_ip', 'N/A')}:{row.get('dst_port', 'N/A'):<25} "
                f"{row.get('protocol', 'N/A'):<10} "
                f"{row.get('final_XGB_prediction', 'N/A')} ({row.get('final_XGB_confidence', 0.0) * 100:.2f}%) "
                f"{row.get('final_DT_prediction', 'N/A')} ({row.get('final_DT_confidence', 0.0) * 100:.2f}%)"
            )
        print("\nA .csv file of all the predicted flows besides BENIGN can be downloaded for further analysis!")
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()