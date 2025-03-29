#!/usr/bin/env python3
import argparse
import pandas as pd
import joblib
import requests
import time
from url_feature_extractor import url_detect_feature_extract

class URLScanner:
    def __init__(self):
        self.models = self._load_models()
        
    def _load_models(self):
        """Load all trained models and ensemble metadata"""
        try:
            return {
                'full': joblib.load('full_features_model.pkl'),
                'reduced': joblib.load('reduced_features_model.pkl'),
                'ensemble_meta': joblib.load('robust_ensemble.pkl')
            }
        except Exception as e:
            raise RuntimeError(f"Failed to load models: {str(e)}")
    
    def scan(self, url, virustotal_key=None):
        """Scan a URL using all models and ensemble"""
        try:
            # Extract features
            features = pd.DataFrame([url_detect_feature_extract(url)])
            
            # Get predictions from both models
            full_pred, full_prob = self._predict_with_model(features, 'full')
            reduced_pred, reduced_prob = self._predict_with_model(features, 'reduced')
            
            # Calculate ensemble prediction (70% full + 30% reduced)
            ensemble_prob = 0.7 * full_prob + 0.3 * reduced_prob
            ensemble_pred = int(ensemble_prob > 0.5)
            
            # Get VirusTotal results if API key provided
            vt_results = None
            if virustotal_key:
                vt_results = self._check_virustotal(url, virustotal_key)
            
            return {
                'url': url,
                'full_prediction': 'Malicious' if full_pred else 'Safe',
                'full_confidence': f"{max(full_prob, 1-full_prob):.1%}",
                'reduced_prediction': 'Malicious' if reduced_pred else 'Safe',
                'reduced_confidence': f"{max(reduced_prob, 1-reduced_prob):.1%}",
                'ensemble_prediction': 'Malicious' if ensemble_pred else 'Safe',
                'ensemble_confidence': f"{max(ensemble_prob, 1-ensemble_prob):.1%}",
                'virustotal': vt_results
            }
            
        except Exception as e:
            raise RuntimeError(f"Scan failed: {str(e)}")
    
    def _predict_with_model(self, features, model_type):
        """Get prediction and probability from a model"""
        model = self.models[model_type]
        scaler = self.models['ensemble_meta']['scalers'][0 if model_type == 'full' else 1]
        features_to_use = self.models['ensemble_meta']['feature_sets'][0 if model_type == 'full' else 1]
        
        scaled_features = scaler.transform(features[features_to_use])
        pred = model.predict(scaled_features)[0]
        proba = model.predict_proba(scaled_features)[0][1]
        return pred, proba
    
    def _check_virustotal(self, url, api_key):
        """Check URL with VirusTotal (with processing delay)"""
        headers = {"x-apikey": api_key}
        try:
            # Submit URL
            print("\nSubmitting to VirusTotal...")
            submit_response = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=15
            )
            submit_response.raise_for_status()
            
            # Wait for analysis
            analysis_id = submit_response.json()['data']['id']
            print("Waiting for VirusTotal analysis (20-30 seconds)...")
            time.sleep(25)
            
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

def display_results(results):
    """Display formatted results"""
    print("\n" + "="*60)
    print("URL THREAT ANALYSIS RESULTS".center(60))
    print("="*60)
    
    print(f"\nURL: {results['url']}")
    
    print("\n--- Model Predictions ---")
    print(f"Full Features: {results['full_prediction']} ({results['full_confidence']})")
    print(f"Reduced Features: {results['reduced_prediction']} ({results['reduced_confidence']})")
    print(f"\nENSEMBLE DECISION: {results['ensemble_prediction']} ({results['ensemble_confidence']})")
    
    if results['virustotal']:
        print("\n--- VirusTotal Verification ---")
        if 'error' in results['virustotal']:
            print(f"Error: {results['virustotal']['error']}")
        else:
            print(f"Detection Ratio: {results['virustotal']['malicious']}/{results['virustotal']['total']}")
            if results['virustotal']['malicious'] > 0:
                print("\nThreat Details:")
                for engine, count in results['virustotal']['details'].items():
                    print(f"  • {engine}: {count}")

def main():
    print("\nE-CAT: URL Detector")
    print("-------------------")
    
    parser = argparse.ArgumentParser(
        description="URL Threat Detection System with Ensemble Model",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('url', help="URL to analyze")
    parser.add_argument('--virustotal', help="VirusTotal API key (optional)")
    args = parser.parse_args()
    
    try:
        print(f"\nAnalyzing: {args.url}")
        scanner = URLScanner()
        results = scanner.scan(args.url, args.virustotal)
        display_results(results)
        
    except Exception as e:
        print(f"\nError during analysis: {str(e)}")
    finally:
        print("\nAnalysis complete.")

if __name__ == "__main__":
    main()