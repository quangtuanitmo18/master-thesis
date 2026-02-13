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
RESULTS_DIR = Path("results")

def load_result_types():
    """Find available result types (e.g., optimized, baseline)."""
    if not RESULTS_DIR.exists():
        st.error(f"Results directory not found: {RESULTS_DIR}")
        return []
    
    types = []
    for item in RESULTS_DIR.iterdir():
        if item.is_dir() and not item.name.startswith('.'):
            types.append(item.name)
    return sorted(types)

def load_available_models(result_type):
    """Find all models with results in the specific result type directory."""
    type_dir = RESULTS_DIR / result_type
    if not type_dir.exists():
        return []
    
    models = []
    for item in type_dir.iterdir():
        if item.is_dir() and (item / "evaluation_summary.csv").exists():
            models.append(item.name)
    return sorted(models)

def load_model_data(result_type, model_names):
    """Load evaluation data for specific models."""
    all_metrics = []
    all_detailed = []
    
    for model_name in model_names:
        model_dir = RESULTS_DIR / result_type / model_name
        summary_path = model_dir / "evaluation_summary.csv"
        detailed_path = model_dir / "evaluation_detailed.csv"
        
        try:
            # Load summary
            summary_df = pd.read_csv(summary_path)
            metrics = summary_df.iloc[0].to_dict()
            metrics['Model'] = model_name
            all_metrics.append(metrics)
            
            # Load detailed
            detailed_df = pd.read_csv(detailed_path)
            detailed_df['Model'] = model_name
            all_detailed.append(detailed_df)
            
        except Exception as e:
            st.error(f"Error loading data for {model_name}: {e}")
            continue
            
    if not all_metrics:
        return None, None
        
    metrics_df = pd.DataFrame(all_metrics)
    combined_detailed_df = pd.concat(all_detailed, ignore_index=True)
    
    return metrics_df, combined_detailed_df

def main():
    st.title("🛡️ OpenVuln Analysis Dashboard")
    st.markdown("Visualize and analyze LLM vulnerability detection results on real-world projects.")
    
    # Sidebar - Configuration
    st.sidebar.header("Configuration")
    
    # Select Result Type
    result_types = load_result_types()
    if not result_types:
        st.warning("No result directories found in `results/`.")
        return
        
    selected_type = st.sidebar.selectbox("Select Result Type", result_types)
    
    # Select Models (Multi-select)
    available_models = load_available_models(selected_type)
    if not available_models:
        st.warning(f"No evaluated models found in `results/{selected_type}`.")
        return

    # Default to select all if fewer than 5, else just the first one
    default_models = available_models
    selected_models = st.sidebar.multiselect("Select Models to Compare", available_models, default=default_models)
    
    if not selected_models:
        st.info("Please select at least one model to view results.")
        return
    
    # Load data
    metrics_df, df = load_model_data(selected_type, selected_models)
    
    if metrics_df is not None and df is not None:
        # --- Metrics Comparison ---
        st.header("📊 Model Comparison")
        
        # Reorder columns for better display
        display_cols = ['Model', 'precision', 'recall', 'f1_score', 'accuracy', 'tp', 'tn', 'fp', 'fn']
        # Format metrics as percentages for display
        metrics_display = metrics_df[display_cols].copy()
        for col in ['precision', 'recall', 'f1_score', 'accuracy']:
             metrics_display[col] = metrics_display[col].apply(lambda x: f"{x:.2%}")
        
        st.dataframe(metrics_display, use_container_width=True, hide_index=True)
        
        st.markdown("---")
        
        # --- Charts ---
        col_chart1, col_chart2 = st.columns(2)
        
        with col_chart1:
            st.subheader("Performance by Model")
            # Melt for chart
            metrics_melted = metrics_df.melt(id_vars='Model', value_vars=['precision', 'recall', 'f1_score', 'accuracy'], 
                                            var_name='Metric', value_name='Value')
            
            fig_perf = px.bar(metrics_melted, x='Metric', y='Value', color='Model', barmode='group',
                             title="Overall Metrics Comparison")
            st.plotly_chart(fig_perf, use_container_width=True)
            
        with col_chart2:
            st.subheader("Weakness Type (CWE) Accuracy")
            # Calculate accuracy per CWE per Model
            cwe_stats = df.groupby(['Model', 'CWE']).apply(lambda x: pd.Series({
                'Accuracy': (x['classification'].isin(['TP', 'TN'])).mean(),
                'Count': len(x)
            })).reset_index()
            
            fig_cwe = px.bar(
                cwe_stats, x='CWE', y='Accuracy',
                color='Model', barmode='group',
                hover_data=['Count'],
                title="Accuracy by CWE"
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
            filtered_df[['Model', 'project_slug', 'CWE', 'filename', 'classification', 'Confidence', 'is_vulnerable', 'llm_predicts_vulnerable']],
            use_container_width=True,
            hide_index=True
        )
        
        # --- Single Alert Inspector ---
        st.subheader("🧐 Alert Inspector")
        st.caption("Select an alert from the table above to view code context.")
        
        # Create a unique key for selection
        filtered_df['display_key'] = filtered_df.apply(lambda x: f"[{x['Model']}] {x['filename']} - {x['classification']}", axis=1)
        
        selected_alert_key = st.selectbox(
            "Select an alert to inspect:",
            filtered_df['display_key'].unique()
        )
        
        if selected_alert_key:
            # Get the first match (should be unique enough with Model + filename)
            alert = filtered_df[filtered_df['display_key'] == selected_alert_key].iloc[0]
            
            c1, c2 = st.columns(2)
            with c1:
                st.info(f"**Model:** {alert['Model']}")
                st.write(f"**Result:** {alert['classification']}")
                st.write(f"**Actually Vulnerable:** {alert['is_vulnerable']}")
                st.write(f"**LLM Prediction:** {alert['llm_predicts_vulnerable']}")
            with c2:
                st.write(f"**CWE:** {alert['CWE']}")
                st.write(f"**CVE:** {alert['CVE']}")
                st.write(f"**Confidence:** {alert['Confidence']}")
            
            with st.expander("See Code Context (if available locally)", expanded=True):
                # Try to find the code context file
                # Path format: code-context/{type}/{project_slug}/{filename}
                try:
                    # 1. Try matching the result type (e.g., optimized, baseline)
                    context_path = Path(f"code-context/{selected_type}/{alert['project_slug']}/{alert['filename']}")
                    
                    # 2. Fallback to optimized
                    if not context_path.exists():
                         context_path = Path(f"code-context/optimized/{alert['project_slug']}/{alert['filename']}")
                    
                    # 3. Fallback to baseline
                    if not context_path.exists():
                         context_path = Path(f"code-context/baseline/{alert['project_slug']}/{alert['filename']}")
                    
                    if context_path.exists():
                        with open(context_path, 'r') as f:
                            st.code(f.read(), language='java') # Assuming Java projects
                        st.caption(f"Source: {context_path}")
                    else:
                        st.warning(f"Code context file not found locally. Checked: {context_path}")
                except Exception as e:
                    st.error(f"Error loading code context: {e}")

if __name__ == "__main__":
    main()
