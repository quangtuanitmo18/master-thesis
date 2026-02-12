import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
import json

# Set page config
st.set_page_config(
    page_title="OpenVuln Analysis Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Constants
RESULTS_DIR = Path("results/optimized")

def load_available_models():
    """Find all models with results in the output directory."""
    if not RESULTS_DIR.exists():
        st.error(f"Results directory not found: {RESULTS_DIR}")
        return []
    
    models = []
    for item in RESULTS_DIR.iterdir():
        if item.is_dir() and (item / "evaluation_summary.csv").exists():
            models.append(item.name)
    return sorted(models)

def load_model_data(model_name):
    """Load evaluation data for a specific model."""
    model_dir = RESULTS_DIR / model_name
    summary_path = model_dir / "evaluation_summary.csv"
    detailed_path = model_dir / "evaluation_detailed.csv"
    
    try:
        summary_df = pd.read_csv(summary_path)
        detailed_df = pd.read_csv(detailed_path)
        return summary_df.iloc[0].to_dict(), detailed_df
    except Exception as e:
        st.error(f"Error loading data for {model_name}: {e}")
        return None, None

def main():
    st.title("🛡️ OpenVuln Analysis Dashboard")
    st.markdown("Visualize and analyze LLM vulnerability detection results on real-world projects.")
    
    # Sidebar - Model Selection
    st.sidebar.header("Configuration")
    available_models = load_available_models()
    
    if not available_models:
        st.warning("No analysis results found. Run `analyze_specific_projects.py` and `evaluate_openvuln_results.py` first.")
        return

    selected_model = st.sidebar.selectbox("Select Model", available_models)
    
    # Load data
    metrics, df = load_model_data(selected_model)
    
    if metrics and df is not None:
        # --- Top Metric Cards ---
        st.header(f"📊 Assessment: {selected_model}")
        
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Precision", f"{metrics['precision']:.2%}")
        col2.metric("Recall", f"{metrics['recall']:.2%}")
        col3.metric("F1 Score", f"{metrics['f1_score']:.2%}")
        col4.metric("Accuracy", f"{metrics['accuracy']:.2%}")
        
        st.markdown("---")
        
        # --- Charts Row ---
        col_chart1, col_chart2 = st.columns(2)
        
        with col_chart1:
            st.subheader("Confusion Matrix")
            # Create Confusion Matrix Data
            cm_data = {
                'Actual Positive': [metrics['tp'], metrics['fn']],
                'Actual Negative': [metrics['fp'], metrics['tn']]
            }
            cm_df = pd.DataFrame(cm_data, index=['Predicted Positive', 'Predicted Negative'])
            
            # Heatmap using Plotly
            z = [[metrics['tn'], metrics['fp']], [metrics['fn'], metrics['tp']]]
            x = ['Negative', 'Positive']
            y = ['Negative', 'Positive']
            
            fig_cm = go.Figure(data=go.Heatmap(
                z=z, x=x, y=y,
                text=[[f"TN: {metrics['tn']}", f"FP: {metrics['fp']}"], 
                      [f"FN: {metrics['fn']}", f"TP: {metrics['tp']}"]],
                texttemplate="%{text}",
                textfont={"size": 16},
                colorscale='Blues'
            ))
            fig_cm.update_layout(
                xaxis_title="Actual",
                yaxis_title="Predicted",
                width=400, height=400
            )
            st.plotly_chart(fig_cm, use_container_width=True)
            
        with col_chart2:
            st.subheader("Weakness Type (CWE) Performance")
            # Calculate accuracy per CWE
            cwe_stats = df.groupby('CWE').apply(lambda x: pd.Series({
                'Accuracy': (x['classification'].isin(['TP', 'TN'])).mean(),
                'Count': len(x)
            })).reset_index()
            
            fig_cwe = px.bar(
                cwe_stats, x='CWE', y='Accuracy',
                hover_data=['Count'],
                color='Accuracy',
                color_continuous_scale='RdYlGn',
                range_y=[0, 1]
            )
            st.plotly_chart(fig_cwe, use_container_width=True)

        st.markdown("---")

        # --- Detailed Results Table ---
        st.subheader("🔍 Detailed Alert Analysis")
        
        # Filters
        col_f1, col_f2, col_f3 = st.columns(3)
        with col_f1:
            filter_result = st.multiselect("Filter by Result", ['TP', 'TN', 'FP', 'FN'], default=['TP', 'TN', 'FP', 'FN'])
        with col_f2:
            filter_cwe = st.multiselect("Filter by CWE", df['CWE'].unique(), default=df['CWE'].unique())
        with col_f3:
            filter_project = st.multiselect("Filter by Project", df['project_slug'].unique(), default=df['project_slug'].unique())
            
        # Apply filters
        filtered_df = df[
            (df['classification'].isin(filter_result)) &
            (df['CWE'].isin(filter_cwe)) &
            (df['project_slug'].isin(filter_project))
        ]
        
        st.dataframe(
            filtered_df[['project_slug', 'CWE', 'filename', 'classification', 'Confidence', 'is_vulnerable', 'llm_predicts_vulnerable']],
            use_container_width=True
        )
        
        # --- Single Alert Inspector ---
        st.subheader("🧐 Alert Inspector")
        selected_alert_idx = st.selectbox(
            "Select an alert to inspect details:",
            filtered_df.index,
            format_func=lambda x: f"[{filtered_df.loc[x, 'classification']}] {filtered_df.loc[x, 'filename']} ({filtered_df.loc[x, 'project_slug']})"
        )
        
        if selected_alert_idx is not None:
            alert = filtered_df.loc[selected_alert_idx]
            
            c1, c2 = st.columns(2)
            with c1:
                st.info(f"**Result:** {alert['classification']}")
                st.write(f"**Actually Vulnerable:** {alert['is_vulnerable']}")
                st.write(f"**LLM Prediction:** {alert['llm_predicts_vulnerable']}")
            with c2:
                st.write(f"**CWE:** {alert['CWE']}")
                st.write(f"**CVE:** {alert['CVE']}")
                st.write(f"**Confidnece:** {alert['Confidence']}")
            
            with st.expander("See Code Context (if available locally)"):
                # Try to find the code context file
                # Path format in CSV: code-context/optimized/project_slug/filename
                # We need to adjust relative path
                try:
                    context_path = Path(f"code-context/optimized/{alert['project_slug']}/{alert['filename']}")
                    if not context_path.exists():
                         # Try baseline if optimized not found
                         context_path = Path(f"code-context/baseline/{alert['project_slug']}/{alert['filename']}")
                    
                    if context_path.exists():
                        with open(context_path, 'r') as f:
                            st.code(f.read(), language='java') # Assuming Java projects
                    else:
                        st.warning("Code context file not found locally.")
                except Exception as e:
                    st.error(f"Error loading code context: {e}")

if __name__ == "__main__":
    main()
