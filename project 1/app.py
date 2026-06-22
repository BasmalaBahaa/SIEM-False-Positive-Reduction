import streamlit as st
import pandas as pd
import numpy as np
import joblib
import os
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, classification_report
import plotly.express as px
import plotly.graph_objects as go
from sklearn.preprocessing import StandardScaler
import base64
from io import BytesIO

# ✅ Set page config FIRST — before any st.write/st.title
st.set_page_config(
    page_title="Network Anomaly Detection",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Define paths - use absolute paths for Streamlit Cloud
STREAMLIT_CLOUD_MODEL_PATH = "/mount/src/networktrafficanomalyandthreatclassification/Models/BinaryClassification-xgboost/outputs/xgboost_model.pkl"
STREAMLIT_CLOUD_SCALER_PATH = "/mount/src/networktrafficanomalyandthreatclassification/Models/BinaryClassification-xgboost/outputs/scaler.pkl"

# Local paths (for development)
LOCAL_MODEL_PATH = "Models/BinaryClassification-xgboost/outputs/xgboost_model.pkl"
LOCAL_SCALER_PATH = "Models/BinaryClassification-xgboost/outputs/scaler.pkl"


# Custom CSS for better appearance
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1E88E5;
        text-align: center;
        margin-bottom: 1rem;
    }
    .section-header {
        font-size: 1.5rem;
        color: #0D47A1;
        margin-top: 1rem;
        margin-bottom: 0.5rem;
    }
    .box {
        padding: 1rem;
        border-radius: 0.5rem;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        margin-bottom: 1rem;
    }
    .info-box {
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
    }
    .warning-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #FFECB3;
        margin-bottom: 1rem;
    }
    .success-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #E8F5E9;
        margin-bottom: 1rem;
    }
</style>
""", unsafe_allow_html=True)

# App title and introduction
st.markdown("<h1 class='main-header'>Network Traffic Anomaly Detection</h1>", unsafe_allow_html=True)

st.markdown("""
<div class='info-box'>
    <p>This application helps you detect network anomalies in your CSV data. Upload your network traffic data, 
    and the application will use a pre-trained XGBoost model to identify potential anomalies.</p>
</div>
""", unsafe_allow_html=True)

# Sidebar for model loading and configuration
with st.sidebar:
    st.markdown("<h2 class='section-header'>Model Configuration</h2>", unsafe_allow_html=True)
    
    model_path = st.file_uploader("Upload model file (.pkl)", type=["pkl"], key="model_uploader")
    scaler_path = st.file_uploader("Upload scaler file (.pkl)", type=["pkl"], key="scaler_uploader")
    
    st.markdown("### OR")
    
    use_default = st.checkbox("Use default model", value=True)
    
    st.markdown("<h2 class='section-header'>Settings</h2>", unsafe_allow_html=True)
    threshold = st.slider("Anomaly threshold probability", 0.0, 1.0, 0.5, 0.01)
    show_advanced = st.checkbox("Show advanced analysis", value=False)
    
    st.markdown("<h2 class='section-header'>About</h2>", unsafe_allow_html=True)
    st.markdown("""
    This app uses XGBoost to detect network anomalies. 
    
    The model was trained on the NF-CSE-CIC-IDS2018 dataset.
    """)

# Function to load model and scaler
@st.cache_resource
def load_model_and_scaler(model_path=None, scaler_path=None, use_default=True):
    if use_default:
        # Try Streamlit Cloud paths first, then local paths
        if os.path.exists(STREAMLIT_CLOUD_MODEL_PATH) and os.path.exists(STREAMLIT_CLOUD_SCALER_PATH):
            model_path = STREAMLIT_CLOUD_MODEL_PATH
            scaler_path = STREAMLIT_CLOUD_SCALER_PATH
            
        elif os.path.exists(LOCAL_MODEL_PATH) and os.path.exists(LOCAL_SCALER_PATH):
            model_path = LOCAL_MODEL_PATH
            scaler_path = LOCAL_SCALER_PATH
            
        else:
            st.error("⚠️ Default model or scaler not found! Make sure both files exist in your repository.")
            st.write("Checked paths:")
            st.write(f"- {STREAMLIT_CLOUD_MODEL_PATH}")
            st.write(f"- {STREAMLIT_CLOUD_SCALER_PATH}")
            st.write(f"- {LOCAL_MODEL_PATH}")
            st.write(f"- {LOCAL_SCALER_PATH}")
            return None, None
    
    try:
        # If file paths were uploaded through Streamlit
        if not isinstance(model_path, str):
            model = joblib.load(BytesIO(model_path.read()))
        else:
            model = joblib.load(model_path)

        if not isinstance(scaler_path, str):
            scaler = joblib.load(BytesIO(scaler_path.read()))
        else:
            scaler = joblib.load(scaler_path)

        st.success(f"✅ Model and scaler loaded successfully!")
        return model, scaler

    except Exception as e:
        st.error(f"❌ Error loading model or scaler: {e}")
        return None, None

# Function to preprocess data
def preprocess_data(df):
    """Remove categorical columns and prepare data for prediction."""
    categorical_cols = [
        'IPV4_SRC_ADDR', 'IPV4_DST_ADDR', 'L4_SRC_PORT', 'L4_DST_PORT', 'PROTOCOL', 'L7_PROTO',
        'TCP_FLAGS', 'CLIENT_TCP_FLAGS', 'SERVER_TCP_FLAGS', 'ICMP_TYPE', 'ICMP_IPV4_TYPE',
        'DNS_QUERY_ID', 'DNS_QUERY_TYPE', 'FTP_COMMAND_RET_CODE', 'SRC_IP_CLASS', 'DST_IP_CLASS',
        'ICMP_TYPE_LABEL', 'ICMP_IPV4_TYPE_LABEL', 'DNS_QUERY_TYPE_LABEL', 'FTP_RET_CATEGORY',
        'PROTOCOL_LABEL', 'L7_PROTO_LABEL', 'SRC_PORT_CATEGORY', 'DST_PORT_CATEGORY',
        'DST_SERVICE', 'SRC_SERVICE'
    ]
    
    # Check if target columns exist
    has_labels = ('Label' in df.columns)
    if has_labels:
        # For evaluation mode (with known labels)
        df_cleaned = df.drop(columns=categorical_cols, errors='ignore')
        y = df_cleaned['Label'] if 'Label' in df_cleaned.columns else None
        X = df_cleaned.drop(columns=['Label', 'Attack', 'Attack_Category'], errors='ignore')
        return X, y, has_labels
    else:
        # For prediction mode (without labels)
        df_cleaned = df.drop(columns=categorical_cols, errors='ignore')
        return df_cleaned, None, has_labels

# Function to make predictions
def predict_anomalies(model, scaler, X, threshold=0.5):
    """Make predictions and return results."""
    # Scale the features
    X_scaled = scaler.transform(X)
    
    # Get probabilities
    y_prob = model.predict_proba(X_scaled)[:, 1]
    
    # Apply threshold
    y_pred = (y_prob >= threshold).astype(int)
    
    return y_pred, y_prob

# Function to plot confusion matrix
def plot_confusion_matrix(y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred)
    fig, ax = plt.subplots(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['Normal', 'Anomaly'],
                yticklabels=['Normal', 'Anomaly'],
                ax=ax)
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.title('Confusion Matrix')
    return fig

# Function to generate feature importance plot
def plot_feature_importance(model, feature_names, top_n=20):
    # Create feature importance DataFrame
    importance = model.feature_importances_
    feature_importance_df = pd.DataFrame({
        'Feature': feature_names,
        'Importance': importance
    }).sort_values('Importance', ascending=False)
    
    # Get top N features
    top_n = min(top_n, len(feature_importance_df))
    top_features = feature_importance_df.head(top_n)
    
    # Create plotly figure
    fig = go.Figure()
    fig.add_trace(go.Bar(
        y=top_features['Feature'],
        x=top_features['Importance'],
        orientation='h',
        marker=dict(color=top_features['Importance'], colorscale='Viridis')
    ))
    
    fig.update_layout(
        title='Top Features by Importance',
        xaxis_title='Importance Score',
        yaxis_title='Feature',
        height=600,
        width=800
    )
    
    return fig, feature_importance_df

# Function to create an interactive scatter plot for anomaly visualization
def create_anomaly_scatter(df, y_pred, y_prob, features_to_plot=None):
    if features_to_plot is None or len(features_to_plot) < 2:
        # If no specific features are provided, use top 2 features with highest variance
        if df.shape[1] >= 2:
            variances = df.var().sort_values(ascending=False)
            features_to_plot = variances.index[:2].tolist()
        else:
            st.warning("Not enough features for scatter plot")
            return None
    
    plot_df = pd.DataFrame({
        'Feature1': df[features_to_plot[0]],
        'Feature2': df[features_to_plot[1]],
        'Predicted': y_pred,
        'Probability': y_prob
    })
    
    fig = px.scatter(
        plot_df, 
        x='Feature1', 
        y='Feature2', 
        color='Predicted',
        color_discrete_map={0: 'blue', 1: 'red'},
        hover_data=['Probability'],
        labels={
            'Predicted': 'Anomaly Prediction',
            'Feature1': features_to_plot[0],
            'Feature2': features_to_plot[1]
        },
        title=f'Anomaly Detection Visualization using {features_to_plot[0]} and {features_to_plot[1]}'
    )
    
    return fig

# Function to download predictions as CSV
def get_table_download_link(df, filename="predictions.csv"):
    csv = df.to_csv(index=False)
    b64 = base64.b64encode(csv.encode()).decode()
    href = f'<a href="data:file/csv;base64,{b64}" download="{filename}">Download CSV File</a>'
    return href

# Main application flow
def main():
    # Load model and scaler
    model, scaler = load_model_and_scaler(model_path, scaler_path, use_default)
    
    # Only show upload section if model loading failed
    if model is None or scaler is None:
        st.warning("⚠️ Please upload your model and scaler files or ensure default files are present.")
        return
    
    # Create tabs for Main Analysis, Test Dataset, and Real-time Monitoring
    tab1, tab2, tab3 = st.tabs(["Main Analysis", "Test Dataset", "Real-time Monitoring"])
    
    # Main Analysis Tab
    with tab1:
        # Upload data file
        st.markdown("<h2 class='section-header'>Upload Data</h2>", unsafe_allow_html=True)
        uploaded_file = st.file_uploader("Choose a CSV file", type=["csv"], key="main_uploader")
        
        # Only proceed if we have data
        if uploaded_file is not None:
            st.markdown("<div class='success-box'>Data uploaded successfully! Processing...</div>", unsafe_allow_html=True)
            
            # Load and display data
            df = pd.read_csv(uploaded_file)
            with st.expander("Preview Data"):
                st.write(df.head())
                st.write(f"Shape: {df.shape}")
            
            # Preprocess data
            X, y, has_labels = preprocess_data(df)
            
            if X.empty:
                st.error("Error: No valid features found in the data after preprocessing")
                return
                
            # Make predictions
            with st.spinner('Making predictions...'):
                y_pred, y_prob = predict_anomalies(model, scaler, X, threshold)
            
            # Display results
            st.markdown("<h2 class='section-header'>Results</h2>", unsafe_allow_html=True)
            
            # Create results DataFrame
            results_df = df.copy()
            results_df['Anomaly_Prediction'] = y_pred
            results_df['Anomaly_Probability'] = y_prob
            
            # Summary statistics
            st.markdown("<h3>Prediction Summary</h3>", unsafe_allow_html=True)
            
            # Display in columns
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Records", len(results_df))
            with col2:
                st.metric("Detected Anomalies", sum(y_pred))
            with col3:
                st.metric("Anomaly %", f"{(sum(y_pred) / len(y_pred) * 100):.2f}%")
            
            # Visualization
            st.markdown("<h3>Visualization</h3>", unsafe_allow_html=True)
            
            # Select features for visualization
            feature_cols = X.columns.tolist()
            
            # If we have more than 1 feature, create a scatter plot with 2 features
            if len(feature_cols) >= 2:
                if show_advanced:
                    # Let user select features
                    col1, col2 = st.columns(2)
                    with col1:
                        feature1 = st.selectbox("Select X-axis feature", feature_cols, index=0)
                    with col2:
                        remaining_features = [f for f in feature_cols if f != feature1]
                        feature2 = st.selectbox("Select Y-axis feature", remaining_features, index=0)
                    selected_features = [feature1, feature2]
                else:
                    # Use top 2 features by variance
                    variances = X.var().sort_values(ascending=False)
                    selected_features = variances.index[:2].tolist()
                
                # Create scatter plot
                scatter_fig = create_anomaly_scatter(X, y_pred, y_prob, selected_features)
                if scatter_fig:
                    st.plotly_chart(scatter_fig, use_container_width=True)
            
            # Display feature importance
            st.markdown("<h3>Feature Importance</h3>", unsafe_allow_html=True)
            importance_fig, importance_df = plot_feature_importance(model, X.columns)
            st.plotly_chart(importance_fig, use_container_width=True)
            
            # Evaluation metrics if true labels are available
            if has_labels and y is not None:
                st.markdown("<h3>Model Evaluation</h3>", unsafe_allow_html=True)
                
                # Display confusion matrix
                st.subheader("Confusion Matrix")
                cm_fig = plot_confusion_matrix(y, y_pred)
                st.pyplot(cm_fig)
                
                # Display classification report
                st.subheader("Classification Report")
                report = classification_report(y, y_pred, output_dict=True)
                report_df = pd.DataFrame(report).transpose()
                st.table(report_df)
            
            # Advanced analysis
            if show_advanced:
                st.markdown("<h3>Advanced Analysis</h3>", unsafe_allow_html=True)
                
                # Distribution of anomaly probabilities
                st.subheader("Anomaly Probability Distribution")
                fig = px.histogram(
                    results_df, 
                    x='Anomaly_Probability',
                    color='Anomaly_Prediction',
                    marginal='violin',
                    nbins=50,
                    title='Distribution of Anomaly Probabilities'
                )
                st.plotly_chart(fig, use_container_width=True)
                
                # Display feature importance table
                st.subheader("Feature Importance Rankings")
                st.dataframe(importance_df)
                
                # Give option to download feature importance as CSV
                st.markdown(
                    get_table_download_link(importance_df, "feature_importance.csv"),
                    unsafe_allow_html=True
                )
            
            # Display predicted results table
            st.markdown("<h3>Prediction Results</h3>", unsafe_allow_html=True)
            
            # Filter options
            show_filter = st.checkbox("Show only anomalies", value=False)
            if show_filter:
                filtered_results = results_df[results_df['Anomaly_Prediction'] == 1]
            else:
                filtered_results = results_df
            
            # Display results
            st.dataframe(filtered_results)
            
            # Give option to download full results as CSV
            st.markdown(
                get_table_download_link(results_df, "anomaly_predictions.csv"),
                unsafe_allow_html=True
            )
    
    # Test Dataset Tab
    with tab2:
        st.markdown("<h2 class='section-header'>Test Dataset Upload</h2>", unsafe_allow_html=True)
        st.markdown("""
        <div class='info-box'>
            <p>Upload a test dataset to evaluate the model performance. This section is specifically for testing and evaluation purposes.</p>
        </div>
        """, unsafe_allow_html=True)
        
        test_file = st.file_uploader("Upload test CSV file", type=["csv"], key="test_uploader")
        
        if test_file is not None:
            st.markdown("<div class='success-box'>Test dataset uploaded successfully! Processing...</div>", unsafe_allow_html=True)
            
            # Load and display test data
            test_df = pd.read_csv(test_file)
            with st.expander("Preview Test Data"):
                st.write(test_df.head())
                st.write(f"Shape: {test_df.shape}")
            
            # Preprocess test data
            X_test, y_test, has_test_labels = preprocess_data(test_df)
            
            if X_test.empty:
                st.error("Error: No valid features found in the test data after preprocessing")
                return
            
            # Make predictions on test data
            with st.spinner('Making predictions on test data...'):
                y_test_pred, y_test_prob = predict_anomalies(model, scaler, X_test, threshold)
            
            # Display test results
            st.markdown("<h2 class='section-header'>Test Results</h2>", unsafe_allow_html=True)
            
            # Create test results DataFrame
            test_results_df = test_df.copy()
            test_results_df['Anomaly_Prediction'] = y_test_pred
            test_results_df['Anomaly_Probability'] = y_test_prob
            
            # Summary statistics
            st.markdown("<h3>Test Prediction Summary</h3>", unsafe_allow_html=True)
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Test Records", len(test_results_df))
            with col2:
                st.metric("Detected Anomalies", sum(y_test_pred))
            with col3:
                st.metric("Anomaly %", f"{(sum(y_test_pred) / len(y_test_pred) * 100):.2f}%")
            
            # If test data has labels, show evaluation metrics
            if has_test_labels and y_test is not None:
                st.markdown("<h3>Test Evaluation Metrics</h3>", unsafe_allow_html=True)
                
                # Confusion Matrix
                st.subheader("Confusion Matrix")
                test_cm_fig = plot_confusion_matrix(y_test, y_test_pred)
                st.pyplot(test_cm_fig)
                
                # Classification Report
                st.subheader("Classification Report")
                test_report = classification_report(y_test, y_test_pred, output_dict=True)
                test_report_df = pd.DataFrame(test_report).transpose()
                st.table(test_report_df)
                
                # Additional metrics
                st.subheader("Detailed Metrics")
                from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
                
                accuracy = accuracy_score(y_test, y_test_pred)
                precision = precision_score(y_test, y_test_pred)
                recall = recall_score(y_test, y_test_pred)
                f1 = f1_score(y_test, y_test_pred)
                
                metrics_col1, metrics_col2 = st.columns(2)
                with metrics_col1:
                    st.metric("Accuracy", f"{accuracy:.4f}")
                    st.metric("Precision", f"{precision:.4f}")
                with metrics_col2:
                    st.metric("Recall", f"{recall:.4f}")
                    st.metric("F1 Score", f"{f1:.4f}")
            else:
                st.info("ℹ️ Test data does not contain ground truth labels. Only predictions are shown.")
            
            # Visualization
            st.markdown("<h3>Test Visualization</h3>", unsafe_allow_html=True)
            
            # Select features for visualization
            test_feature_cols = X_test.columns.tolist()
            
            if len(test_feature_cols) >= 2:
                # Use top 2 features by variance
                test_variances = X_test.var().sort_values(ascending=False)
                test_selected_features = test_variances.index[:2].tolist()
                
                # Create scatter plot
                test_scatter_fig = create_anomaly_scatter(X_test, y_test_pred, y_test_prob, test_selected_features)
                if test_scatter_fig:
                    st.plotly_chart(test_scatter_fig, use_container_width=True)
            
            # Feature importance for test data
            st.markdown("<h3>Feature Importance</h3>", unsafe_allow_html=True)
            test_importance_fig, test_importance_df = plot_feature_importance(model, X_test.columns)
            st.plotly_chart(test_importance_fig, use_container_width=True)
            
            # Display test results table
            st.markdown("<h3>Test Prediction Results</h3>", unsafe_allow_html=True)
            
            # Filter options
            test_show_filter = st.checkbox("Show only anomalies", value=False, key="test_filter")
            if test_show_filter:
                test_filtered_results = test_results_df[test_results_df['Anomaly_Prediction'] == 1]
            else:
                test_filtered_results = test_results_df
            
            # Display results
            st.dataframe(test_filtered_results)
            
            # Give option to download test results as CSV
            st.markdown(
                get_table_download_link(test_results_df, "test_predictions.csv"),
                unsafe_allow_html=True
            )
    
    # Real-time Monitoring Tab
    with tab3:
        st.markdown("<h2 class='section-header'>Real-time Monitoring</h2>", unsafe_allow_html=True)
        st.markdown("""
        <div class='info-box'>
            <p>Monitor network traffic in real-time for anomaly detection. Upload files continuously or use simulated data streaming for continuous monitoring.</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Initialize session state for real-time monitoring
        if 'real_time_data' not in st.session_state:
            st.session_state.real_time_data = pd.DataFrame()
            st.session_state.anomaly_count = 0
            st.session_state.total_processed = 0
            st.session_state.alerts = []
            st.session_state.start_time = pd.Timestamp.now()
        
        # Real-time settings
        st.markdown("<h3>Monitoring Settings</h3>", unsafe_allow_html=True)
        col1, col2, col3 = st.columns(3)
        with col1:
            refresh_interval = st.slider("Refresh interval (seconds)", 1, 10, 2)
        with col2:
            alert_threshold = st.slider("Alert threshold", 0.5, 1.0, 0.7, 0.05)
        with col3:
            max_history = st.slider("Max history records", 100, 1000, 500)
        
        # Continuous File Upload Section (Always Visible)
        st.markdown("<h3>📁 Continuous File Upload</h3>", unsafe_allow_html=True)
        st.markdown("""
        <div class='info-box'>
            <p>Upload CSV files for real-time anomaly detection. Each uploaded file will be processed immediately and results will be added to the monitoring dashboard.</p>
        </div>
        """, unsafe_allow_html=True)
        
        continuous_upload = st.file_uploader("Upload CSV file", type=["csv"], key="continuous_upload")
        
        # Control buttons
        control_col1, control_col2, control_col3 = st.columns(3)
        with control_col1:
            if st.button("▶ Start Monitoring", key="start_monitoring"):
                st.session_state.monitoring_active = True
                st.session_state.start_time = pd.Timestamp.now()
                st.success("Monitoring started!")
                st.rerun()
        
        with control_col2:
            if st.button("⏹ Stop Monitoring", key="stop_monitoring"):
                st.session_state.monitoring_active = False
                st.warning("Monitoring stopped!")
                st.rerun()
        
        with control_col3:
            if st.button("🗑 Clear History", key="clear_history"):
                st.session_state.real_time_data = pd.DataFrame()
                st.session_state.anomaly_count = 0
                st.session_state.total_processed = 0
                st.session_state.alerts = []
                st.success("History cleared!")
                st.rerun()
        
        # Process uploaded files
        if continuous_upload is not None:
            try:
                # Process the uploaded file
                new_df = pd.read_csv(continuous_upload)
                st.success(f"✅ File uploaded successfully! Processing {len(new_df)} records...")
                
                # Preprocess and predict
                X_new, y_new, has_labels = preprocess_data(new_df)
                
                if not X_new.empty:
                    # Make predictions
                    y_pred_new, y_prob_new = predict_anomalies(model, scaler, X_new, alert_threshold)
                    
                    # Add predictions to data
                    new_df['Anomaly_Prediction'] = y_pred_new
                    new_df['Anomaly_Probability'] = y_prob_new
                    new_df['Timestamp'] = pd.Timestamp.now()
                    
                    # Update session state
                    if st.session_state.real_time_data.empty:
                        st.session_state.real_time_data = new_df
                    else:
                        st.session_state.real_time_data = pd.concat([
                            st.session_state.real_time_data, 
                            new_df
                        ], ignore_index=True)
                    
                    # Keep only max_history records
                    if len(st.session_state.real_time_data) > max_history:
                        st.session_state.real_time_data = st.session_state.real_time_data.tail(max_history)
                    
                    # Update counters
                    st.session_state.total_processed += len(new_df)
                    new_anomalies = sum(y_pred_new)
                    st.session_state.anomaly_count += new_anomalies
                    
                    # Generate alerts for new anomalies
                    if new_anomalies > 0:
                        anomaly_records = new_df[new_df['Anomaly_Prediction'] == 1]
                        for _, row in anomaly_records.iterrows():
                            alert = {
                                'timestamp': row['Timestamp'],
                                'probability': row['Anomaly_Probability'],
                                'details': f"Anomaly detected in uploaded file (Prob: {row['Anomaly_Probability']:.2f})"
                            }
                            st.session_state.alerts.append(alert)
                            # Keep only last 50 alerts
                            if len(st.session_state.alerts) > 50:
                                st.session_state.alerts = st.session_state.alerts[-50:]
                    
                    st.success(f"✅ Processing complete! Detected {new_anomalies} anomalies in this file.")
                    st.rerun()
                    
            except Exception as e:
                st.error(f"❌ Error processing uploaded file: {e}")
        
        # Simulated Data Streaming (optional enhancement)
        simulated_mode = st.checkbox("Enable Simulated Data Streaming", value=False, key="simulated_mode")
        if simulated_mode and st.session_state.get('monitoring_active', False):
            # Simulate real-time data stream
            with st.spinner("Processing simulated data..."):
                # Generate simulated network traffic data
                np.random.seed(int(pd.Timestamp.now().timestamp()))
                num_new_records = np.random.randint(1, 5)
                
                # Create sample data matching the expected feature structure
                sample_data = []
                for _ in range(num_new_records):
                    record = {
                        'IN_BYTES': np.random.randint(100, 10000),
                        'OUT_BYTES': np.random.randint(50, 5000),
                        'IN_PKTS': np.random.randint(1, 100),
                        'OUT_PKTS': np.random.randint(1, 50),
                        'FLOW_DURATION_MILLISECONDS': np.random.randint(1000, 60000),
                        'TCP_FLAGS': np.random.randint(0, 255),
                        'PROTOCOL': np.random.choice([6, 17, 1]),  # TCP, UDP, ICMP
                    }
                    sample_data.append(record)
                
                new_data = pd.DataFrame(sample_data)
                
                if not new_data.empty:
                    # Preprocess and predict
                    try:
                        X_new, _, _ = preprocess_data(new_data)
                        if not X_new.empty:
                            # Make predictions
                            y_pred_new, y_prob_new = predict_anomalies(model, scaler, X_new, alert_threshold)
                            
                            # Add predictions to data
                            new_data['Anomaly_Prediction'] = y_pred_new
                            new_data['Anomaly_Probability'] = y_prob_new
                            new_data['Timestamp'] = pd.Timestamp.now()
                            
                            # Update session state
                            st.session_state.real_time_data = pd.concat([
                                st.session_state.real_time_data, 
                                new_data
                            ], ignore_index=True)
                            
                            # Keep only max_history records
                            if len(st.session_state.real_time_data) > max_history:
                                st.session_state.real_time_data = st.session_state.real_time_data.tail(max_history)
                            
                            # Update counters
                            st.session_state.total_processed += len(new_data)
                            new_anomalies = sum(y_pred_new)
                            st.session_state.anomaly_count += new_anomalies
                            
                            # Generate alerts for new anomalies
                            if new_anomalies > 0:
                                anomaly_records = new_data[new_data['Anomaly_Prediction'] == 1]
                                for _, row in anomaly_records.iterrows():
                                    alert = {
                                        'timestamp': row['Timestamp'],
                                        'probability': row['Anomaly_Probability'],
                                        'details': f"Anomaly detected (Prob: {row['Anomaly_Probability']:.2f})"
                                    }
                                    st.session_state.alerts.append(alert)
                                    # Keep only last 50 alerts
                                    if len(st.session_state.alerts) > 50:
                                        st.session_state.alerts = st.session_state.alerts[-50:]
                    
                    except Exception as e:
                        st.error(f"Error processing simulated data: {e}")
            
            # Auto-refresh
            placeholder = st.empty()
            with placeholder:
                st.info(f"🔄 Auto-refreshing every {refresh_interval} seconds... (Monitoring Active)")
                time.sleep(refresh_interval)
                st.rerun()
            
            # Control buttons for continuous upload
            control_col1, control_col2 = st.columns(2)
            with control_col1:
                if st.button("🗑 Clear History", key="clear_upload_history"):
                    st.session_state.real_time_data = pd.DataFrame()
                    st.session_state.anomaly_count = 0
                    st.session_state.total_processed = 0
                    st.session_state.alerts = []
                    st.success("History cleared!")
                    st.rerun()
            
            if continuous_upload is not None:
                try:
                    # Process the uploaded file
                    new_df = pd.read_csv(continuous_upload)
                    st.success(f"✅ File uploaded successfully! Processing {len(new_df)} records...")
                    
                    # Preprocess and predict
                    X_new, y_new, has_labels = preprocess_data(new_df)
                    
                    if not X_new.empty:
                        # Make predictions
                        y_pred_new, y_prob_new = predict_anomalies(model, scaler, X_new, alert_threshold)
                        
                        # Add predictions to data
                        new_df['Anomaly_Prediction'] = y_pred_new
                        new_df['Anomaly_Probability'] = y_prob_new
                        new_df['Timestamp'] = pd.Timestamp.now()
                        
                        # Update session state
                        if st.session_state.real_time_data.empty:
                            st.session_state.real_time_data = new_df
                        else:
                            st.session_state.real_time_data = pd.concat([
                                st.session_state.real_time_data, 
                                new_df
                            ], ignore_index=True)
                        
                        # Keep only max_history records
                        if len(st.session_state.real_time_data) > max_history:
                            st.session_state.real_time_data = st.session_state.real_time_data.tail(max_history)
                        
                        # Update counters
                        st.session_state.total_processed += len(new_df)
                        new_anomalies = sum(y_pred_new)
                        st.session_state.anomaly_count += new_anomalies
                        
                        # Generate alerts for new anomalies
                        if new_anomalies > 0:
                            anomaly_records = new_df[new_df['Anomaly_Prediction'] == 1]
                            for _, row in anomaly_records.iterrows():
                                alert = {
                                    'timestamp': row['Timestamp'],
                                    'probability': row['Anomaly_Probability'],
                                    'details': f"Anomaly detected in uploaded file (Prob: {row['Anomaly_Probability']:.2f})"
                                }
                                st.session_state.alerts.append(alert)
                                # Keep only last 50 alerts
                                if len(st.session_state.alerts) > 50:
                                    st.session_state.alerts = st.session_state.alerts[-50:]
                        
                        st.success(f"✅ Processing complete! Detected {new_anomalies} anomalies in this file.")
                        st.rerun()
                        
                except Exception as e:
                    st.error(f"❌ Error processing uploaded file: {e}")
        
        else:  # Simulated Data Streaming mode
            # Real-time settings for simulated streaming
            st.markdown("<h3>Monitoring Settings</h3>", unsafe_allow_html=True)
            col1, col2, col3 = st.columns(3)
            with col1:
                refresh_interval = st.slider("Refresh interval (seconds)", 1, 10, 2)
            with col2:
                alert_threshold = st.slider("Alert threshold", 0.5, 1.0, 0.7, 0.05)
            with col3:
                max_history = st.slider("Max history records", 100, 1000, 500)
            
            # Control buttons
            control_col1, control_col2, control_col3 = st.columns(3)
            with control_col1:
                if st.button("▶ Start Monitoring", key="start_monitoring"):
                    st.session_state.monitoring_active = True
                    st.session_state.start_time = pd.Timestamp.now()
                    st.success("Monitoring started!")
                    st.rerun()
            
            with control_col2:
                if st.button("⏹ Stop Monitoring", key="stop_monitoring"):
                    st.session_state.monitoring_active = False
                    st.warning("Monitoring stopped!")
                    st.rerun()
            
            with control_col3:
                if st.button("🗑 Clear History", key="clear_history"):
                    st.session_state.real_time_data = pd.DataFrame()
                    st.session_state.anomaly_count = 0
                    st.session_state.total_processed = 0
                    st.session_state.alerts = []
                    st.success("History cleared!")
                    st.rerun()
        
        # Simulated Data Streaming mode processing
        if monitoring_mode == "Simulated Data Streaming" and st.session_state.get('monitoring_active', False):
            # Simulate real-time data stream (replace with actual data source in production)
            with st.spinner("Processing real-time data..."):
                # Generate simulated network traffic data
                np.random.seed(int(pd.Timestamp.now().timestamp()))
                num_new_records = np.random.randint(1, 5)
                
                # Create sample data matching the expected feature structure
                sample_data = []
                for _ in range(num_new_records):
                    record = {
                        'IN_BYTES': np.random.randint(100, 10000),
                        'OUT_BYTES': np.random.randint(50, 5000),
                        'IN_PKTS': np.random.randint(1, 100),
                        'OUT_PKTS': np.random.randint(1, 50),
                        'FLOW_DURATION_MILLISECONDS': np.random.randint(1000, 60000),
                        'TCP_FLAGS': np.random.randint(0, 255),
                        'PROTOCOL': np.random.choice([6, 17, 1]),  # TCP, UDP, ICMP
                    }
                    sample_data.append(record)
                
                new_data = pd.DataFrame(sample_data)
                
                if not new_data.empty:
                    # Preprocess and predict
                    try:
                        X_new, _, _ = preprocess_data(new_data)
                        if not X_new.empty:
                            # Make predictions
                            y_pred_new, y_prob_new = predict_anomalies(model, scaler, X_new, alert_threshold)
                            
                            # Add predictions to data
                            new_data['Anomaly_Prediction'] = y_pred_new
                            new_data['Anomaly_Probability'] = y_prob_new
                            new_data['Timestamp'] = pd.Timestamp.now()
                            
                            # Update session state
                            st.session_state.real_time_data = pd.concat([
                                st.session_state.real_time_data, 
                                new_data
                            ], ignore_index=True)
                            
                            # Keep only max_history records
                            if len(st.session_state.real_time_data) > max_history:
                                st.session_state.real_time_data = st.session_state.real_time_data.tail(max_history)
                            
                            # Update counters
                            st.session_state.total_processed += len(new_data)
                            new_anomalies = sum(y_pred_new)
                            st.session_state.anomaly_count += new_anomalies
                            
                            # Generate alerts for new anomalies
                            if new_anomalies > 0:
                                anomaly_records = new_data[new_data['Anomaly_Prediction'] == 1]
                                for _, row in anomaly_records.iterrows():
                                    alert = {
                                        'timestamp': row['Timestamp'],
                                        'probability': row['Anomaly_Probability'],
                                        'details': f"Anomaly detected (Prob: {row['Anomaly_Probability']:.2f})"
                                    }
                                    st.session_state.alerts.append(alert)
                                    # Keep only last 50 alerts
                                    if len(st.session_state.alerts) > 50:
                                        st.session_state.alerts = st.session_state.alerts[-50:]
                    
                    except Exception as e:
                        st.error(f"Error processing real-time data: {e}")
            
            # Auto-refresh using placeholder
            placeholder = st.empty()
            with placeholder:
                st.info(f"🔄 Auto-refreshing every {refresh_interval} seconds... (Monitoring Active)")
                time.sleep(refresh_interval)
                st.rerun()
        
        # Display real-time monitoring dashboard
        if not st.session_state.real_time_data.empty:
            st.markdown("<h3>Live Dashboard</h3>", unsafe_allow_html=True)
            
            # Key metrics
            metric_col1, metric_col2, metric_col3, metric_col4 = st.columns(4)
            with metric_col1:
                st.metric("Total Processed", st.session_state.total_processed)
            with metric_col2:
                st.metric("Anomalies Detected", st.session_state.anomaly_count)
            with metric_col3:
                anomaly_rate = (st.session_state.anomaly_count / max(st.session_state.total_processed, 1)) * 100
                st.metric("Anomaly Rate", f"{anomaly_rate:.2f}%")
            with metric_col4:
                uptime = pd.Timestamp.now() - st.session_state.get('start_time', pd.Timestamp.now())
                st.metric("Uptime", str(uptime).split('.')[0])
            
            # Real-time charts
            chart_col1, chart_col2 = st.columns(2)
            
            with chart_col1:
                st.subheader("Anomaly Detection Over Time")
                if len(st.session_state.real_time_data) > 0:
                    timeline_data = st.session_state.real_time_data.groupby(
                        pd.Grouper(key='Timestamp', freq='1Min')
                    ).agg({
                        'Anomaly_Prediction': ['sum', 'count']
                    }).reset_index()
                    timeline_data.columns = ['Timestamp', 'Anomalies', 'Total']
                    timeline_data['Anomaly_Rate'] = (timeline_data['Anomalies'] / timeline_data['Total'] * 100).fillna(0)
                    
                    fig_timeline = px.line(
                        timeline_data,
                        x='Timestamp',
                        y='Anomaly_Rate',
                        title='Anomaly Rate Over Time',
                        labels={'Anomaly_Rate': 'Anomaly Rate (%)'},
                        markers=True
                    )
                    fig_timeline.update_layout(height=300)
                    st.plotly_chart(fig_timeline, use_container_width=True)
            
            with chart_col2:
                st.subheader("Recent Anomaly Probabilities")
                recent_data = st.session_state.real_time_data.tail(50)
                if not recent_data.empty:
                    fig_prob = px.scatter(
                        recent_data,
                        x=range(len(recent_data)),
                        y='Anomaly_Probability',
                        color='Anomaly_Prediction',
                        color_discrete_map={0: 'blue', 1: 'red'},
                        title='Recent Anomaly Probabilities',
                        labels={'x': 'Recent Records', 'Anomaly_Probability': 'Probability'},
                        size_max=10
                    )
                    fig_prob.add_hline(y=alert_threshold, line_dash="dash", line_color="orange",
                                     annotation_text=f"Alert Threshold: {alert_threshold}")
                    fig_prob.update_layout(height=300)
                    st.plotly_chart(fig_prob, use_container_width=True)
            
            # Recent alerts
            st.markdown("<h3>Recent Alerts</h3>", unsafe_allow_html=True)
            if st.session_state.alerts:
                alerts_df = pd.DataFrame(st.session_state.alerts)
                alerts_df['timestamp'] = pd.to_datetime(alerts_df['timestamp']).dt.strftime('%H:%M:%S')
                st.dataframe(alerts_df.tail(10).iloc[::-1], use_container_width=True)
                
                # Alert notification
                if len(st.session_state.alerts) > 0:
                    latest_alert = st.session_state.alerts[-1]
                    if (pd.Timestamp.now() - latest_alert['timestamp']).total_seconds() < 60:
                        st.error(f"🚨 NEW ALERT: {latest_alert['details']} at {latest_alert['timestamp'].strftime('%H:%M:%S')}")
            else:
                st.info("No alerts generated yet.")
            
            # Recent activity table
            st.markdown("<h3>Recent Activity</h3>", unsafe_allow_html=True)
            recent_activity = st.session_state.real_time_data.tail(20)[['Timestamp', 'Anomaly_Prediction', 'Anomaly_Probability']]
            recent_activity['Timestamp'] = pd.to_datetime(recent_activity['Timestamp']).dt.strftime('%H:%M:%S')
            st.dataframe(recent_activity.iloc[::-1], use_container_width=True)
        else:
            st.info("📡 No data received yet. Click 'Start Monitoring' to begin real-time anomaly detection.")

import time

if __name__ == "__main__":
    main()
