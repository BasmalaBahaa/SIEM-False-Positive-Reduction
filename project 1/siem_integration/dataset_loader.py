"""
Dataset Loading Utilities for Large-Scale Network Log Analysis
Provides functions to load datasets from various sources for training One-Class SVM
"""

import pandas as pd
import numpy as np
import os
from pathlib import Path
from typing import Optional, List
import warnings
warnings.filterwarnings('ignore')

# Try importing optional dependencies
try:
    import kagglehub
    KAGGLE_AVAILABLE = True
except ImportError:
    KAGGLE_AVAILABLE = False
    print("⚠️ kagglehub not available. Install with: pip install kagglehub")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class DatasetLoader:
    """Utility class for loading large-scale network log datasets"""

    CICFLOWMETER_DATASET_PATHS = [
        Path(r"C:\Users\Omar Mohamed\Downloads\Project_1-SIEM-Solution--master (5)\Project_1-SIEM-Solution--master (2)\Project_1-SIEM-Solution--master\Project_1-SIEM-Solution--master\project 1\Notebooks\Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv"),
        Path(r"C:\Users\Omar Mohamed\Downloads\Project_1-SIEM-Solution--master (5)\Project_1-SIEM-Solution--master (2)\Project_1-SIEM-Solution--master\Project_1-SIEM-Solution--master\project 1\Notebooks\Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv"),
    ]

    CICFLOWMETER_FALLBACK_PATHS = [
        Path(__file__).resolve().parents[1] / "data" / "raw" / "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
        Path(__file__).resolve().parents[1] / "data" / "raw" / "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",
    ]
    
    # Recommended datasets for network anomaly detection
    RECOMMENDED_DATASETS = {
        'NF-CSE-CIC-IDS2018': {
            'source': 'kaggle',
            'identifier': 'mohamedelrifai/network-anomaly-detection-dataset',
            'filename': 'sampled_NF-CSE-CIC-IDS2018-v2.csv',
            'description': 'Network Flow dataset with various attack types',
            'size': 'Large (188K+ samples)',
            'features': 'Network flow features',
            'attacks': ['DDoS', 'Brute Force', 'Port Scan', 'SQL Injection', 'XSS']
        },
        'CIC-IDS2017': {
            'source': 'kaggle',
            'identifier': 'cranix/ids2017',
            'description': 'Intrusion Detection System dataset from 2017',
            'size': 'Very Large (2.8M+ samples)',
            'features': 'Network flow features',
            'attacks': ['DDoS', 'Brute Force', 'Port Scan', 'Botnet', 'Infiltration']
        },
        'UNSW-NB15': {
            'source': 'kaggle',
            'identifier': 'mrwellsdavid/unsw-nb15',
            'description': 'Network-based intrusion detection dataset',
            'size': 'Large (257K+ samples)',
            'features': 'Network flow features',
            'attacks': ['Fuzzers', 'Analysis', 'Backdoors', 'DoS', 'Exploits', 'Generic', 'Reconnaissance', 'Shellcode', 'Worms']
        },
        'KDD-CUP-99': {
            'source': 'kaggle',
            'identifier': 'datasets/cesarcasado/kddcup99',
            'description': 'Classic intrusion detection dataset',
            'size': 'Large (494K+ samples)',
            'features': 'Network connection features',
            'attacks': ['DoS', 'Probe', 'R2L', 'U2R']
        }
    }

    @staticmethod
    def validate_and_load_cicflowmeter_datasets(label_column: str = "Label") -> pd.DataFrame:
        """
        Validate, load, inspect, and combine the two CICFlowMeter CSV datasets.

        The original CSV files are only read with pandas. Nothing is written back to disk.
        """
        print("=" * 80)
        print("CICFlowMeter Dataset Preflight Check")
        print("=" * 80)

        try:
            # Check the user-provided paths first.
            dataset_paths = DatasetLoader.CICFLOWMETER_DATASET_PATHS
            missing_paths = [path for path in dataset_paths if not path.exists()]

            # Use the checked-in project copies if the provided Notebooks paths are missing.
            if missing_paths:
                print("The following configured dataset paths were not found:")
                for path in missing_paths:
                    print(f"  - {path}")
                print("\nTrying project data/raw fallback paths...")
                dataset_paths = DatasetLoader.CICFLOWMETER_FALLBACK_PATHS
                missing_paths = [path for path in dataset_paths if not path.exists()]

            # Stop before loading if either selected CSV path is still unavailable.
            if missing_paths:
                missing_list = "\n".join(f"  - {path}" for path in missing_paths)
                raise FileNotFoundError(f"Missing CICFlowMeter CSV file(s):\n{missing_list}")

            dataframes = []

            # Load each CSV safely, then print inspection details for quick verification.
            for index, path in enumerate(dataset_paths, start=1):
                print("\n" + "-" * 80)
                print(f"Loading dataset {index}: {path}")
                df = pd.read_csv(path, low_memory=False)
                dataframes.append(df)

                print(f"Dataset {index} shape: {df.shape}")
                print(f"Dataset {index} columns:")
                print(list(df.columns))
                print(f"Dataset {index} missing values count:")
                print(df.isna().sum())
                print(f"Dataset {index} first 5 rows:")
                print(df.head())

            # Confirm both CSV files have the same schema before combining them.
            same_columns = list(dataframes[0].columns) == list(dataframes[1].columns)
            print("\n" + "-" * 80)
            print(f"Both datasets have the same columns: {same_columns}")
            if not same_columns:
                raise ValueError("The two CICFlowMeter datasets do not have matching columns.")

            # Combine the datasets only after the schemas match.
            combined_df = pd.concat(dataframes, ignore_index=True)
            print(f"Combined dataset shape: {combined_df.shape}")

            # Basic test to make sure the pipeline will not receive an empty dataset.
            if combined_df.empty:
                raise ValueError("Combined CICFlowMeter dataset is empty.")
            print("Basic test passed: combined dataset is not empty.")

            # Check that the label/target column exists before the main pipeline continues.
            if label_column not in combined_df.columns:
                raise KeyError(f"Target column '{label_column}' was not found in the combined dataset.")
            print(f"Target column check passed: '{label_column}' exists.")

            print("=" * 80)
            print("CICFlowMeter Dataset Preflight Check Passed")
            print("=" * 80)
            return combined_df

        except FileNotFoundError as error:
            print(f"[ERROR] Dataset file check failed: {error}")
            raise
        except pd.errors.EmptyDataError as error:
            print(f"[ERROR] One of the CSV files is empty or unreadable: {error}")
            raise
        except pd.errors.ParserError as error:
            print(f"[ERROR] pandas could not parse one of the CSV files: {error}")
            raise
        except Exception as error:
            print(f"[ERROR] CICFlowMeter dataset preflight failed: {error}")
            raise
    
    @staticmethod
    def list_recommended_datasets():
        """List all recommended datasets"""
        print("=" * 80)
        print("Recommended Datasets for Network Anomaly Detection")
        print("=" * 80)
        
        for name, info in DatasetLoader.RECOMMENDED_DATASETS.items():
            print(f"\n[Dataset] {name}")
            print(f"   Description: {info['description']}")
            print(f"   Size: {info['size']}")
            print(f"   Source: {info['source']}")
            if 'identifier' in info:
                print(f"   Identifier: {info['identifier']}")
            if 'filename' in info:
                print(f"   Filename: {info['filename']}")
            print(f"   Attack Types: {', '.join(info['attacks'])}")
        
        print("\n" + "=" * 80)
    
    @staticmethod
    def load_from_kaggle(dataset_identifier: str, filename: Optional[str] = None,
                        sample_size: Optional[int] = None) -> pd.DataFrame:
        """
        Load dataset from Kaggle.
        
        Parameters:
        -----------
        dataset_identifier : str
            Kaggle dataset identifier (e.g., 'mohamedelrifai/network-anomaly-detection-dataset')
        filename : str, optional
            Specific filename within dataset
        sample_size : int, optional
            Number of samples to load (for large datasets)
        
        Returns:
        --------
        pd.DataFrame: Loaded dataset
        """
        if not KAGGLE_AVAILABLE:
            raise ImportError("kagglehub not available. Install with: pip install kagglehub")
        
        print(f"Loading dataset from Kaggle: {dataset_identifier}")
        
        # Download dataset
        path = kagglehub.dataset_download(dataset_identifier)
        
        if filename:
            file_path = os.path.join(path, filename)
        else:
            # Find CSV files in dataset
            files = [f for f in os.listdir(path) if f.endswith('.csv')]
            if not files:
                raise FileNotFoundError(f"No CSV files found in {path}")
            file_path = os.path.join(path, files[0])
            print(f"Using file: {files[0]}")
        
        # Load dataset
        print(f"Loading from: {file_path}")
        
        if sample_size:
            # Load in chunks for large files
            print(f"Loading {sample_size} samples...")
            chunk_list = []
            chunk_size = min(100000, sample_size)
            
            for chunk in pd.read_csv(file_path, chunksize=chunk_size):
                chunk_list.append(chunk)
                if len(chunk_list) * chunk_size >= sample_size:
                    break
            
            df = pd.concat(chunk_list, ignore_index=True)
            if len(df) > sample_size:
                df = df.sample(n=sample_size, random_state=42)
        else:
            df = pd.read_csv(file_path)
        
        print(f"[OK] Dataset loaded: {df.shape[0]} rows, {df.shape[1]} columns")
        return df
    
    @staticmethod
    def load_from_local(file_path: str, sample_size: Optional[int] = None,
                       chunksize: int = 100000) -> pd.DataFrame:
        """
        Load dataset from local file.
        
        Parameters:
        -----------
        file_path : str
            Path to CSV file
        sample_size : int, optional
            Number of samples to load
        chunksize : int
            Chunk size for reading large files
        
        Returns:
        --------
        pd.DataFrame: Loaded dataset
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        print(f"Loading dataset from local file: {file_path}")
        
        # Get file size
        file_size = os.path.getsize(file_path) / (1024 * 1024)  # MB
        print(f"File size: {file_size:.2f} MB")
        
        if sample_size:
            # Load in chunks
            print(f"Loading {sample_size} samples in chunks...")
            chunk_list = []
            
            for chunk in pd.read_csv(file_path, chunksize=chunksize):
                chunk_list.append(chunk)
                if len(chunk_list) * chunksize >= sample_size:
                    break
            
            df = pd.concat(chunk_list, ignore_index=True)
            if len(df) > sample_size:
                df = df.sample(n=sample_size, random_state=42)
        else:
            # Load full file
            if file_size > 500:  # If > 500 MB, use chunks
                print("Large file detected. Loading in chunks...")
                chunk_list = []
                for chunk in pd.read_csv(file_path, chunksize=chunksize):
                    chunk_list.append(chunk)
                df = pd.concat(chunk_list, ignore_index=True)
            else:
                df = pd.read_csv(file_path)
        
        print(f"[OK] Dataset loaded: {df.shape[0]} rows, {df.shape[1]} columns")
        return df
    
    @staticmethod
    def load_recommended_dataset(dataset_name: str, sample_size: Optional[int] = None) -> pd.DataFrame:
        """
        Load a recommended dataset by name.
        
        Parameters:
        -----------
        dataset_name : str
            Name of recommended dataset
        sample_size : int, optional
            Number of samples to load
        
        Returns:
        --------
        pd.DataFrame: Loaded dataset
        """
        if dataset_name not in DatasetLoader.RECOMMENDED_DATASETS:
            available = ', '.join(DatasetLoader.RECOMMENDED_DATASETS.keys())
            raise ValueError(f"Unknown dataset: {dataset_name}. Available: {available}")
        
        info = DatasetLoader.RECOMMENDED_DATASETS[dataset_name]
        
        if info['source'] == 'kaggle':
            filename = info.get('filename')
            return DatasetLoader.load_from_kaggle(
                info['identifier'],
                filename=filename,
                sample_size=sample_size
            )
        else:
            raise ValueError(f"Unsupported source: {info['source']}")
    
    @staticmethod
    def get_dataset_info(dataset_name: str) -> dict:
        """Get information about a recommended dataset"""
        if dataset_name not in DatasetLoader.RECOMMENDED_DATASETS:
            available = ', '.join(DatasetLoader.RECOMMENDED_DATASETS.keys())
            raise ValueError(f"Unknown dataset: {dataset_name}. Available: {available}")
        
        return DatasetLoader.RECOMMENDED_DATASETS[dataset_name]


if __name__ == "__main__":
    # List recommended datasets
    DatasetLoader.list_recommended_datasets()
    
    # Example: Load NF-CSE-CIC-IDS2018 dataset
    print("\n" + "=" * 80)
    print("Example: Loading NF-CSE-CIC-IDS2018 dataset")
    print("=" * 80)
    
    try:
        # Load recommended dataset (sampled for demo)
        df = DatasetLoader.load_recommended_dataset('NF-CSE-CIC-IDS2018', sample_size=10000)
        
        print(f"\nDataset shape: {df.shape}")
        print(f"\nColumns: {list(df.columns[:10])}...")
        
        if 'Label' in df.columns:
            print(f"\nLabel distribution:")
            print(df['Label'].value_counts())
        
        if 'Attack' in df.columns:
            print(f"\nAttack types:")
            print(df['Attack'].value_counts().head(10))
        
    except Exception as e:
        print(f"Error loading dataset: {e}")
