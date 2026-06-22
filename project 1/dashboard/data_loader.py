"""
Data Loader for SIEM Dashboard
Loads and processes SIEM alerts and outlier detection results
"""

import json
import pandas as pd
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
import os
import re


class DashboardDataLoader:
    """Load and process data for the SIEM dashboard"""
    
    def __init__(self, siem_data_path="../siem_integration"):
        self.siem_data_path = siem_data_path
        self.alerts_file = os.path.join(siem_data_path, "siem_alerts.json")
        self.outliers_file = os.path.join(siem_data_path, "outliers_detected.csv")
        self.outlier_summary_file = os.path.join(siem_data_path, "outlier_summary.json")
        project_dir = Path(__file__).resolve().parents[1]
        self.alerts_fallback_file = project_dir / "outputs" / "siem_alerts.json"
        self.outliers_fallback_file = project_dir / "outputs" / "outliers_detected.csv"
        self.cicflowmeter_summary_cache_file = project_dir / "outputs" / "cicflowmeter_summary.json"
        
        # Cache for data with TTL (time-to-live)
        self._alerts_cache = None
        self._outliers_cache = None
        self._cicflowmeter_cache = None
        self._cicflowmeter_last_load_time = None
        self._last_load_time = None
        self._cache_ttl = 5  # Cache TTL in seconds
        self._cicflowmeter_cache_ttl = 300  # Large CSV summaries are cached for 5 minutes.

        self.cicflowmeter_configured_paths = [
            Path(r"C:\Users\Omar Mohamed\Downloads\Project_1-SIEM-Solution--master (5)\Project_1-SIEM-Solution--master (2)\Project_1-SIEM-Solution--master\Project_1-SIEM-Solution--master\project 1\Notebooks\Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv"),
            Path(r"C:\Users\Omar Mohamed\Downloads\Project_1-SIEM-Solution--master (5)\Project_1-SIEM-Solution--master (2)\Project_1-SIEM-Solution--master\Project_1-SIEM-Solution--master\project 1\Notebooks\Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv"),
        ]
        self.cicflowmeter_fallback_paths = [
            project_dir / "data" / "raw" / "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
            project_dir / "data" / "raw" / "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",
        ]

    def _resolve_cicflowmeter_paths(self) -> List[Path]:
        """Return the two CICFlowMeter CSV paths, preferring the configured paths."""
        configured_missing = [path for path in self.cicflowmeter_configured_paths if not path.exists()]
        if not configured_missing:
            return self.cicflowmeter_configured_paths

        fallback_missing = [path for path in self.cicflowmeter_fallback_paths if not path.exists()]
        if fallback_missing:
            missing_list = configured_missing + fallback_missing
            raise FileNotFoundError(
                "Missing CICFlowMeter CSV file(s): "
                + "; ".join(str(path) for path in missing_list)
            )

        return self.cicflowmeter_fallback_paths

    def _resolve_outliers_file(self) -> Path:
        """Return the available outliers CSV path."""
        configured_path = Path(self.outliers_file)
        if configured_path.exists():
            return configured_path
        if self.outliers_fallback_file.exists():
            return self.outliers_fallback_file
        raise FileNotFoundError(
            f"Outliers file not found at {configured_path} or {self.outliers_fallback_file}"
        )

    def _resolve_alerts_file(self) -> Path:
        """Return the available SIEM alerts JSON path."""
        configured_path = Path(self.alerts_file)
        if configured_path.exists():
            return configured_path
        if self.alerts_fallback_file.exists():
            return self.alerts_fallback_file
        raise FileNotFoundError(
            f"Alerts file not found at {configured_path} or {self.alerts_fallback_file}"
        )

    def _load_cicflowmeter_disk_cache(self, paths: List[Path]) -> Optional[Dict]:
        """Load a saved CICFlowMeter summary when it is newer than the CSV files."""
        if not self.cicflowmeter_summary_cache_file.exists():
            return None

        cache_mtime = self.cicflowmeter_summary_cache_file.stat().st_mtime
        newest_dataset_mtime = max(path.stat().st_mtime for path in paths)
        if cache_mtime < newest_dataset_mtime:
            return None

        try:
            with open(self.cicflowmeter_summary_cache_file, "r", encoding="utf-8") as cache_file:
                return json.load(cache_file)
        except (OSError, json.JSONDecodeError):
            return None

    def _save_cicflowmeter_disk_cache(self, summary: Dict) -> None:
        """Persist the expensive CICFlowMeter summary for fast dashboard reloads."""
        try:
            self.cicflowmeter_summary_cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cicflowmeter_summary_cache_file, "w", encoding="utf-8") as cache_file:
                json.dump(summary, cache_file)
        except OSError as error:
            print(f"Could not save CICFlowMeter summary cache: {error}")

    def get_cicflowmeter_summary(self, force_reload: bool = False) -> Dict:
        """
        Build dashboard-ready summaries from the two CICFlowMeter CSV datasets.

        The CSV files are read in chunks and are never modified.
        """
        current_time = datetime.now()
        cache_is_fresh = (
            self._cicflowmeter_cache is not None
            and self._cicflowmeter_last_load_time is not None
            and (current_time - self._cicflowmeter_last_load_time).total_seconds() < self._cicflowmeter_cache_ttl
        )
        if cache_is_fresh and not force_reload:
            return self._cicflowmeter_cache

        paths = self._resolve_cicflowmeter_paths()
        if not force_reload:
            disk_cache = self._load_cicflowmeter_disk_cache(paths)
            if disk_cache is not None:
                self._cicflowmeter_cache = disk_cache
                self._cicflowmeter_last_load_time = current_time
                return disk_cache

        preview_columns = [
            "Timestamp", "Label", "Protocol", "Dst Port", "Flow Duration",
            "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts",
            "Flow Byts/s", "Flow Pkts/s"
        ]
        metric_columns = [
            "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts",
            "TotLen Bwd Pkts", "Flow Byts/s", "Flow Pkts/s"
        ]
        use_columns = list(dict.fromkeys(preview_columns))

        total_rows = 0
        label_counts = {}
        protocol_counts = {}
        top_ports = {}
        hourly_counts = {}
        dataset_rows = []
        metric_sums = {column: 0.0 for column in metric_columns}
        metric_counts = {column: 0 for column in metric_columns}
        sample_rows = []
        all_columns = []
        schema_match = True

        for path in paths:
            header = pd.read_csv(path, nrows=0)
            columns = list(header.columns)
            if not all_columns:
                all_columns = columns
            elif columns != all_columns:
                schema_match = False

            file_rows = 0
            for chunk in pd.read_csv(path, usecols=use_columns, chunksize=100000, low_memory=False):
                file_rows += len(chunk)
                total_rows += len(chunk)

                if len(sample_rows) < 10:
                    needed = 10 - len(sample_rows)
                    sample = chunk.head(needed).replace([float("inf"), float("-inf")], pd.NA)
                    sample_rows.extend(
                        sample.replace({pd.NA: None}).fillna("").to_dict("records")
                    )

                labels = chunk["Label"].fillna("Unknown").astype(str).value_counts()
                for label, count in labels.items():
                    label_counts[label] = label_counts.get(label, 0) + int(count)

                protocols = chunk["Protocol"].fillna("Unknown").astype(str).value_counts()
                for protocol, count in protocols.items():
                    protocol_counts[protocol] = protocol_counts.get(protocol, 0) + int(count)

                ports = chunk["Dst Port"].fillna("Unknown").astype(str).value_counts().head(50)
                for port, count in ports.items():
                    top_ports[port] = top_ports.get(port, 0) + int(count)

                timestamps = pd.to_datetime(chunk["Timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce")
                hours = timestamps.dropna().dt.strftime("%Y-%m-%d %H:00").value_counts()
                for hour, count in hours.items():
                    hourly_counts[hour] = hourly_counts.get(hour, 0) + int(count)

                for column in metric_columns:
                    values = pd.to_numeric(chunk[column], errors="coerce")
                    values = values.replace([float("inf"), float("-inf")], pd.NA)
                    finite_values = values[values.notna()]
                    metric_sums[column] += float(finite_values.sum())
                    metric_counts[column] += int(finite_values.count())

            dataset_rows.append({
                "name": path.name,
                "path": str(path),
                "rows": int(file_rows),
                "columns": int(len(columns)),
                "size_mb": round(path.stat().st_size / (1024 * 1024), 2)
            })

        attack_rows = sum(count for label, count in label_counts.items() if label.lower() != "benign")
        benign_rows = label_counts.get("Benign", 0)
        protocol_names = {"0": "HOPOPT/Other", "1": "ICMP", "6": "TCP", "17": "UDP"}
        sorted_ports = sorted(top_ports.items(), key=lambda item: item[1], reverse=True)[:10]
        sorted_hours = sorted(hourly_counts.items())
        traffic_alerts = []
        for label, count in sorted(label_counts.items(), key=lambda item: item[1], reverse=True):
            if label.lower() == "benign":
                continue

            percentage = (count / total_rows * 100) if total_rows else 0
            severity = "critical" if count >= 100000 else "high" if count >= 25000 else "medium"
            traffic_alerts.append({
                "alert_id": f"CIC-{label.upper().replace(' ', '-').replace('/', '-')}",
                "label": label,
                "severity": severity,
                "flow_count": int(count),
                "percentage": round(percentage, 2),
                "source": "CICFlowMeter",
                "status": "new",
                "recommendation": "Investigate source hosts and correlate with SIEM alerts."
            })

        summary = {
            "files": dataset_rows,
            "schema_match": schema_match,
            "total_rows": int(total_rows),
            "total_columns": int(len(all_columns)),
            "column_names": all_columns,
            "label_counts": label_counts,
            "benign_rows": int(benign_rows),
            "attack_rows": int(attack_rows),
            "traffic_alerts": traffic_alerts,
            "protocol_counts": {
                protocol_names.get(str(protocol), str(protocol)): int(count)
                for protocol, count in protocol_counts.items()
            },
            "top_ports": {
                str(port): int(count)
                for port, count in sorted_ports
            },
            "hourly_traffic": {
                "hours": [hour for hour, _ in sorted_hours],
                "counts": [int(count) for _, count in sorted_hours]
            },
            "feature_means": {
                column: round(metric_sums[column] / metric_counts[column], 2) if metric_counts[column] else 0
                for column in metric_columns
            },
            "sample_rows": sample_rows
        }

        self._cicflowmeter_cache = summary
        self._cicflowmeter_last_load_time = current_time
        self._save_cicflowmeter_disk_cache(summary)
        return summary
    
    def parse_timestamp(self, timestamp_str):
        """Parse timestamp string to datetime object, handling multiple formats"""
        try:
            # Try ISO format with T
            if 'T' in timestamp_str:
                # Remove microseconds if present
                if '.' in timestamp_str:
                    timestamp_str = timestamp_str.split('.')[0]
                return datetime.fromisoformat(timestamp_str.replace('T', ' '))
            # Try space-separated format
            return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
        except:
            # Fallback: return current time if parsing fails
            return datetime.now()
    
    def load_alerts(self, filters=None, force_reload=False) -> List[Dict]:
        """
        Load SIEM alerts from JSON file with caching
        
        Parameters:
        -----------
        filters : dict, optional
            Filters to apply: 'severity', 'status', 'time_range', 'search'
        force_reload : bool, optional
            Force cache reload regardless of TTL
            
        Returns:
        --------
        list: List of alert dictionaries
        """
        current_time = datetime.now()
        
        # Check if we need to reload the data
        if (force_reload or 
            self._alerts_cache is None or 
            self._last_load_time is None or 
            (current_time - self._last_load_time).total_seconds() > self._cache_ttl):
            
            try:
                alerts_file = self._resolve_alerts_file()
                print(f"Loading alerts from {alerts_file}")
                with open(alerts_file, 'r', encoding='utf-8-sig') as f:
                    self._alerts_cache = json.load(f)
                self._last_load_time = current_time
                print(f"Successfully loaded {len(self._alerts_cache)} alerts")
            except FileNotFoundError:
                print(f"Alerts file not found: {self.alerts_file}")
                self._alerts_cache = []
                self._last_load_time = current_time
            except json.JSONDecodeError as e:
                print(f"JSON decode error in alerts file: {e}")
                self._alerts_cache = []
                self._last_load_time = current_time
        
        alerts = self._alerts_cache.copy() if self._alerts_cache else []
        
        if not filters:
            return alerts
        
        filtered = alerts
        
        # Filter by severity
        if 'severity' in filters and filters['severity']:
            filtered = [a for a in filtered if a.get('severity') == filters['severity']]
        
        # Filter by status
        if 'status' in filters and filters['status']:
            filtered = [a for a in filtered if a.get('status') == filters['status']]
        
        # Filter by time range
        if 'time_range' in filters and filters['time_range']:
            hours = filters['time_range']
            cutoff_time = datetime.now() - timedelta(hours=hours)
            filtered = [a for a in filtered 
                       if self.parse_timestamp(a['timestamp']) >= cutoff_time]
        
        # Search filter
        if 'search' in filters and filters['search']:
            search_term = filters['search'].lower()
            filtered = [a for a in filtered 
                       if search_term in str(a).lower()]
        
        return filtered
    
    def load_outliers(self, filters=None) -> pd.DataFrame:
        """
        Load outlier detection results from CSV file
        
        Parameters:
        -----------
        filters : dict, optional
            Filters to apply: 'detection_method', 'search'
            
        Returns:
        --------
        pd.DataFrame: Outliers dataframe
        """
        try:
            df = pd.read_csv(self._resolve_outliers_file())
        except FileNotFoundError:
            return pd.DataFrame()
        
        if not filters:
            return df
        
        filtered = df.copy()
        
        # Filter by detection method
        if 'detection_method' in filters and filters['detection_method']:
            method = filters['detection_method']
            if method == 'IQR':
                filtered = filtered[filtered['IQR_Outlier'] == 1]
            elif method == 'ZScore':
                filtered = filtered[filtered['ZScore_Outlier'] == 1]
            elif method == 'IsolationForest':
                filtered = filtered[filtered['IsolationForest_Outlier'] == 1]
        
        # Search filter
        if 'search' in filters and filters['search']:
            search_term = filters['search'].lower()
            mask = filtered.astype(str).apply(lambda x: x.str.contains(search_term, case=False)).any(axis=1)
            filtered = filtered[mask]
        
        return filtered
    
    def get_statistics(self) -> Dict:
        """
        Calculate KPIs and summary statistics
        
        Returns:
        --------
        dict: Statistics dictionary
        """
        alerts = self.load_alerts()
        outliers = self.load_outliers()
        
        # Alert statistics
        total_alerts = len(alerts)
        high_severity = sum(1 for a in alerts if a.get('severity') == 'high')
        medium_severity = sum(1 for a in alerts if a.get('severity') == 'medium')
        low_severity = sum(1 for a in alerts if a.get('severity') == 'low')
        
        # Status counts
        new_alerts = sum(1 for a in alerts if a.get('status') == 'new')
        investigating = sum(1 for a in alerts if a.get('status') == 'investigating')
        resolved = sum(1 for a in alerts if a.get('status') == 'resolved')
        
        # Outlier statistics
        total_outliers = len(outliers)
        iqr_outliers = outliers['IQR_Outlier'].sum() if not outliers.empty else 0
        zscore_outliers = outliers['ZScore_Outlier'].sum() if not outliers.empty else 0
        iso_outliers = outliers['IsolationForest_Outlier'].sum() if not outliers.empty else 0
        
        # Top anomalous files
        top_files = []
        if not outliers.empty:
            # Calculate a combined score for ranking
            outliers_copy = outliers.copy()
            outliers_copy['combined_score'] = (
                outliers_copy['IQR_Outlier'] + 
                outliers_copy['ZScore_Outlier'] + 
                outliers_copy['IsolationForest_Outlier']
            )
            top_files = outliers_copy.nlargest(10, 'combined_score')[
                ['Filename', 'combined_score', 'malfind.ninjections', 
                 'pslist.nproc', 'handles.nhandles']
            ].to_dict('records')
        
        # Time series data (alerts over time)
        alert_timeline = []
        if alerts:
            # Group alerts by hour
            for alert in alerts:
                try:
                    timestamp = datetime.fromisoformat(alert['timestamp'])
                    alert_timeline.append(timestamp)
                except:
                    continue
            
            if alert_timeline:
                # Create hourly bins for the last 24 hours
                now = datetime.now()
                hours = []
                counts = []
                for i in range(24, 0, -1):
                    hour_start = now - timedelta(hours=i)
                    hour_end = now - timedelta(hours=i-1)
                    count = sum(1 for t in alert_timeline if hour_start <= t < hour_end)
                    hours.append(hour_start.strftime('%H:00'))
                    counts.append(count)
                
                alert_timeline = {'hours': hours, 'counts': counts}
            else:
                alert_timeline = {'hours': [], 'counts': []}
        else:
            alert_timeline = {'hours': [], 'counts': []}
        
        return {
            'total_alerts': total_alerts,
            'high_severity': high_severity,
            'medium_severity': medium_severity,
            'low_severity': low_severity,
            'new_alerts': new_alerts,
            'investigating': investigating,
            'resolved': resolved,
            'total_outliers': total_outliers,
            'iqr_outliers': int(iqr_outliers),
            'zscore_outliers': int(zscore_outliers),
            'iso_outliers': int(iso_outliers),
            'top_files': top_files,
            'alert_timeline': alert_timeline
        }
    
    def search(self, query: str, search_type: str = 'all') -> Dict:
        """
        Search across alerts and outliers
        
        Parameters:
        -----------
        query : str
            Search query (supports regex if enabled)
        search_type : str
            Type of search: 'all', 'alerts', 'outliers'
            
        Returns:
        --------
        dict: Search results
        """
        results = {
            'query': query,
            'alerts': [],
            'outliers': []
        }
        
        if not query:
            return results
        
        # Search alerts
        if search_type in ['all', 'alerts']:
            alerts = self.load_alerts({'search': query})
            results['alerts'] = alerts
        
        # Search outliers
        if search_type in ['all', 'outliers']:
            outliers = self.load_outliers({'search': query})
            results['outliers'] = outliers.to_dict('records') if not outliers.empty else []
        
        return results
    
    def get_alert_by_id(self, alert_id: str) -> Optional[Dict]:
        """Get a specific alert by ID"""
        alerts = self.load_alerts()
        for alert in alerts:
            if alert.get('alert_id') == alert_id:
                return alert
        return None
    
    def get_recent_alerts(self, limit: int = 10) -> List[Dict]:
        """Get most recent alerts"""
        alerts = self.load_alerts()
        # Sort by timestamp descending
        sorted_alerts = sorted(alerts, 
                             key=lambda x: x.get('timestamp', ''), 
                             reverse=True)
        return sorted_alerts[:limit]
    
    def get_severity_distribution(self) -> Dict:
        """Get alert severity distribution for pie chart"""
        alerts = self.load_alerts()
        severity_counts = {'high': 0, 'medium': 0, 'low': 0}
        
        for alert in alerts:
            severity = alert.get('severity', 'low')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return severity_counts
    
    def get_detection_method_comparison(self) -> Dict:
        """Get outlier detection method comparison"""
        outliers = self.load_outliers()
        
        if outliers.empty:
            return {'IQR': 0, 'Z-Score': 0, 'Isolation Forest': 0}
        
        return {
            'IQR': int(outliers['IQR_Outlier'].sum()),
            'Z-Score': int(outliers['ZScore_Outlier'].sum()),
            'Isolation Forest': int(outliers['IsolationForest_Outlier'].sum())
        }
