#!/usr/bin/env python3
"""
Evaluate OpenVuln LLM results against ground truth.
Compare LLM predictions with actual vulnerabilities and calculate metrics.
"""

import pandas as pd
import argparse
from pathlib import Path

def load_ground_truth(ground_truth_path):
    """Load and parse ground truth CSV."""
    df = pd.read_csv(ground_truth_path)
    print(f"✅ Loaded ground truth: {len(df)} alerts")
    return df

def load_llm_results(results_path):
    """Load LLM analysis results CSV."""
    df = pd.read_csv(results_path)
    print(f"✅ Loaded LLM results: {len(df)} alerts")
    return df

def extract_filename_from_alert_name(alert_name):
    """Extract base filename from alert_name (e.g., 'vulnerability_java_xss_1' -> 'vulnerability_java_xss_1.txt')."""
    return f"{alert_name}.txt"

def merge_results_with_ground_truth(llm_df, gt_df):
    """Merge LLM predictions with ground truth labels."""
    
    # Extract filename from alert_name for matching
    llm_df['filename'] = llm_df['alert_name'].apply(extract_filename_from_alert_name)
    
    # Merge on project_slug and filename
    merged = pd.merge(
        llm_df,
        gt_df[['project_slug', 'filename', 'is_vulnerable']],
        on=['project_slug', 'filename'],
        how='inner'
    )
    
    print(f"✅ Matched {len(merged)} alerts with ground truth")
    
    if len(merged) != len(llm_df):
        unmatched = len(llm_df) - len(merged)
        print(f"⚠️  Warning: {unmatched} alerts from LLM results not found in ground truth")
    
    return merged

def calculate_metrics(merged_df):
    """Calculate TP, TN, FP, FN and metrics."""
    
    # LLM prediction: "False Positive" column
    # - "No" means LLM thinks it's VULNERABLE (not a false positive)
    # - "Yes" means LLM thinks it's NOT VULNERABLE (false positive)
    
    # Ground truth: is_vulnerable column
    # - True = actually vulnerable
    # - False = not vulnerable
    
    # Convert LLM's "False Positive" to predicted vulnerability
    merged_df['llm_predicts_vulnerable'] = merged_df['False Positive'] == 'No'
    merged_df['actually_vulnerable'] = merged_df['is_vulnerable'] == True
    
    # Calculate confusion matrix
    tp = len(merged_df[(merged_df['llm_predicts_vulnerable'] == True) & (merged_df['actually_vulnerable'] == True)])
    tn = len(merged_df[(merged_df['llm_predicts_vulnerable'] == False) & (merged_df['actually_vulnerable'] == False)])
    fp = len(merged_df[(merged_df['llm_predicts_vulnerable'] == True) & (merged_df['actually_vulnerable'] == False)])
    fn = len(merged_df[(merged_df['llm_predicts_vulnerable'] == False) & (merged_df['actually_vulnerable'] == True)])
    
    # Calculate metrics
    total = tp + tn + fp + fn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    accuracy = (tp + tn) / total if total > 0 else 0
    
    return {
        'tp': tp,
        'tn': tn, 
        'fp': fp,
        'fn': fn,
        'total': total,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'accuracy': accuracy
    }

def print_evaluation_report(metrics, model_name):
    """Print formatted evaluation report."""
    print("\n" + "="*60)
    print(f"📊 Evaluation Results: {model_name}")
    print("="*60)
    print(f"\n🔢 Confusion Matrix:")
    print(f"  True Positives (TP):   {metrics['tp']:3d}")
    print(f"  True Negatives (TN):   {metrics['tn']:3d}")
    print(f"  False Positives (FP):  {metrics['fp']:3d}")
    print(f"  False Negatives (FN):  {metrics['fn']:3d}")
    print(f"  Total:                 {metrics['total']:3d}")
    
    print(f"\n📈 Performance Metrics:")
    print(f"  Precision:  {metrics['precision']:.4f} ({metrics['precision']*100:.2f}%)")
    print(f"  Recall:     {metrics['recall']:.4f} ({metrics['recall']*100:.2f}%)")
    print(f"  F1 Score:   {metrics['f1']:.4f} ({metrics['f1']*100:.2f}%)")
    print(f"  Accuracy:   {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)")
    print("="*60 + "\n")

def save_detailed_results(merged_df, output_dir):
    """Save detailed per-alert results."""
    output_path = output_dir / "evaluation_detailed.csv"
    
    # Add prediction columns for clarity
    result_df = merged_df[[
        'project_slug', 'CVE', 'CWE', 'filename', 'alert_name',
        'False Positive', 'Sanitization Found?', 'Attack Feasible?', 'Confidence',
        'is_vulnerable', 'llm_predicts_vulnerable', 'actually_vulnerable'
    ]].copy()
    
    # Add classification result
    result_df['classification'] = result_df.apply(
        lambda row: 
            'TP' if row['llm_predicts_vulnerable'] and row['actually_vulnerable'] else
            'TN' if not row['llm_predicts_vulnerable'] and not row['actually_vulnerable'] else
            'FP' if row['llm_predicts_vulnerable'] and not row['actually_vulnerable'] else
            'FN',
        axis=1
    )
    
    result_df.to_csv(output_path, index=False)
    print(f"💾 Saved detailed results to: {output_path}")

def save_summary_report(metrics, model_name, output_dir):
    """Save summary metrics to CSV."""
    output_path = output_dir / "evaluation_summary.csv"
    
    summary_df = pd.DataFrame([{
        'model': model_name,
        'tp': metrics['tp'],
        'tn': metrics['tn'],
        'fp': metrics['fp'],
        'fn': metrics['fn'],
        'precision': metrics['precision'],
        'recall': metrics['recall'],
        'f1_score': metrics['f1'],
        'accuracy': metrics['accuracy']
    }])
    
    summary_df.to_csv(output_path, index=False)
    print(f"💾 Saved summary to: {output_path}")

def main():
    parser = argparse.ArgumentParser(description="Evaluate OpenVuln LLM results against ground truth")
    parser.add_argument("--results", required=True, help="Path to LLM results CSV (openrouter_prompts_responses.csv)")
    parser.add_argument("--ground-truth", default="ground_truth.csv", help="Path to ground truth CSV")
    parser.add_argument("--model-name", help="Model name for reporting (auto-detected from results if not provided)")
    
    args = parser.parse_args()
    
    # Load data
    gt_df = load_ground_truth(args.ground_truth)
    llm_df = load_llm_results(args.results)
    
    # Auto-detect model name from results if not provided
    if args.model_name:
        model_name = args.model_name
    elif 'model_used' in llm_df.columns:
        model_name = llm_df['model_used'].iloc[0]
    else:
        model_name = "Unknown Model"
    
    # Merge and evaluate
    merged_df = merge_results_with_ground_truth(llm_df, gt_df)
    metrics = calculate_metrics(merged_df)
    
    # Print report
    print_evaluation_report(metrics, model_name)
    
    # Save results
    output_dir = Path(args.results).parent
    save_detailed_results(merged_df, output_dir)
    save_summary_report(metrics, model_name, output_dir)
    
    print("✅ Evaluation complete!")

if __name__ == "__main__":
    main()
