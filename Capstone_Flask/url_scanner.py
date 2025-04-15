import pandas as pd
import joblib
import requests
import time
import os
from url_feature_extractor import url_detect_feature_extract

class URLScanner:
    def __init__(self):
        self.models = self._load_models()
        
    def _load_models(self):
        """Load all trained models with error handling"""
        try:
            model_dir = os.path.join('models', 'url_models')
            
            return {
                'full': joblib.load(os.path.join(model_dir, 'full_features_model.joblib')),
                'reduced': joblib.load(os.path.join(model_dir, 'reduced_features_model.joblib')),
                'ensemble_meta': joblib.load(os.path.join(model_dir, 'robust_ensemble.joblib'))
            }
        except Exception as e:
            raise RuntimeError(f"Failed to load models: {str(e)}")
    
    def scan(self, url, virustotal_key=None):
        """Scan a URL with comprehensive error handling"""
        try:
            # Validate URL format
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            # Extract features
            features = pd.DataFrame([url_detect_feature_extract(url)])
            
            # Get predictions
            full_pred, full_prob = self._predict_with_model(features, 'full')
            reduced_pred, reduced_prob = self._predict_with_model(features, 'reduced')
            
            # Calculate confidence percentages (0-100 scale)
            full_confidence = max(full_prob, 1-full_prob) * 100
            reduced_confidence = max(reduced_prob, 1-reduced_prob) * 100
            
            # Ensemble prediction
            ensemble_prob = 0.7 * full_prob + 0.3 * reduced_prob
            ensemble_pred = int(ensemble_prob > 0.5)
            ensemble_confidence = max(ensemble_prob, 1-ensemble_prob) * 100
            
            # VirusTotal check
            vt_results = None
            if virustotal_key:
                vt_results = self._check_virustotal(url, virustotal_key)
            
            return {
                'url': url,
                'full_prediction': 'Malicious' if full_pred else 'Safe',
                'full_confidence': f"{full_confidence:.1f}%",
                'full_confidence_raw': full_confidence,
                'reduced_prediction': 'Malicious' if reduced_pred else 'Safe',
                'reduced_confidence': f"{reduced_confidence:.1f}%",
                'reduced_confidence_raw': reduced_confidence,
                'ensemble_prediction': 'Malicious' if ensemble_pred else 'Safe',
                'ensemble_confidence': f"{ensemble_confidence:.1f}%",
                'ensemble_confidence_raw': ensemble_confidence,
                'virustotal': vt_results
            }
            
        except Exception as e:
            raise RuntimeError(f"Scan failed: {str(e)}")
    
    def _predict_with_model(self, features, model_type):
        """Helper method for model prediction"""
        model = self.models[model_type]
        scaler = self.models['ensemble_meta']['scalers'][0 if model_type == 'full' else 1]
        features_to_use = self.models['ensemble_meta']['feature_sets'][0 if model_type == 'full' else 1]
        
        scaled_features = scaler.transform(features[features_to_use])
        pred = model.predict(scaled_features)[0]
        proba = model.predict_proba(scaled_features)[0][1]
        return pred, proba
    
    def _check_virustotal(self, url, api_key):
        """Check URL with VirusTotal"""
        headers = {"x-apikey": api_key}
        try:
            # Submit URL
            submit_response = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=15
            )
            submit_response.raise_for_status()
            
            # Get analysis ID
            analysis_id = submit_response.json()['data']['id']
            time.sleep(20)  # Reduced wait time
            
            # Get report
            report_response = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=15
            )
            report_response.raise_for_status()
            
            stats = report_response.json()['data']['attributes']['stats']
            return {
                'malicious': stats.get('malicious', 0),
                'total': sum(stats.values()),
                'details': {k:v for k,v in stats.items() if v > 0}
            }
            
        except requests.exceptions.RequestException as e:
            return {'error': f"VirusTotal API error: {str(e)}"}
        except Exception as e:
            return {'error': str(e)}