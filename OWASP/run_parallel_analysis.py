#!/usr/bin/env python3
"""
Parallel Analysis Runner for OWASP False Positive Reduction

This script runs multiple analysis jobs in parallel using different combinations of:
- Datasets (owasp)
- Prompt versions (baseline, optimized)
- Models (o4-mini, gemini, claude, ...)
- CWEs (078, 079, 089, ...)

Usage:
    python run_parallel_analysis.py --datasets owasp --prompt-versions optimized --models o4-mini --cwes CWE-078 CWE-079 --threads 4
"""

import argparse
import logging
import os
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('parallel_analysis.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class AnalysisJob:
    """
    Represents a single analysis job configuration.
    
    This dataclass encapsulates all parameters needed to run one analysis:
    - Which dataset to analyze (e.g., "owasp")
    - Which prompt template version to use (e.g., "baseline", "optimized")
    - Which LLM model to use (e.g., "o4-mini", "google/gemini-2.5-pro")
    - Which CWE to analyze (e.g., "CWE-078", "CWE-079")
    - A unique job ID for tracking
    
    Attributes:
        dataset: Dataset name (currently only "owasp" supported)
        prompt_version: Prompt template version ("baseline" or "optimized")
        model: LLM model identifier (may include provider prefix like "google/")
        cwe: CWE identifier (e.g., "CWE-078")
        job_id: Unique identifier for this job (auto-generated if not provided)
    """
    dataset: str
    prompt_version: str
    model: str
    cwe: str
    job_id: str = ""
    
    def __post_init__(self):
        """
        Auto-generate job_id if not provided.
        
        Job ID format: {prompt_version}_{dataset}_{cwe}_{model}
        Model names with "/" are sanitized to "_" and ":" to "-" for filesystem compatibility.
        Windows doesn't allow colons in filenames.
        """
        if not self.job_id:
            self.job_id = f"{self.prompt_version}_{self.dataset}_{self.cwe}_{self.model.replace('/', '_').replace(':', '-')}"

class ProgressTracker:
    """
    Thread-safe progress tracker for parallel analysis jobs.
    
    This class tracks the status of multiple jobs running in parallel:
    - Total number of jobs
    - Number of completed jobs
    - Number of failed jobs
    - Number of currently running jobs
    - Calculates progress percentage and ETA
    
    Uses threading.Lock to ensure thread-safe updates when multiple
    threads report job status simultaneously.
    """
    
    def __init__(self, total_jobs: int):
        """
        Initialize progress tracker.
        
        Args:
            total_jobs: Total number of jobs to track
        """
        self.total_jobs = total_jobs
        self.completed_jobs = 0
        self.failed_jobs = 0
        self.running_jobs = 0
        self.lock = threading.Lock()  # Thread-safe lock for concurrent updates
        self.start_time = time.time()  # Track start time for ETA calculation
        
    def job_started(self, job_id: str):
        """
        Mark a job as started.
        
        Thread-safe method to increment running_jobs counter.
        
        Args:
            job_id: Unique identifier of the job that started
        """
        with self.lock:
            self.running_jobs += 1
            logger.info(f"🚀 Started job: {job_id} (Running: {self.running_jobs}/{self.total_jobs})")
    
    def job_completed(self, job_id: str, success: bool = True):
        """
        Mark a job as completed (successfully or with failure).
        
        Thread-safe method to update job counters and print progress.
        
        Args:
            job_id: Unique identifier of the completed job
            success: True if job succeeded, False if it failed
        """
        with self.lock:
            self.running_jobs -= 1
            if success:
                self.completed_jobs += 1
                logger.info(f"✅ Completed job: {job_id} (Completed: {self.completed_jobs}/{self.total_jobs})")
            else:
                self.failed_jobs += 1
                logger.error(f"❌ Failed job: {job_id} (Failed: {self.failed_jobs}/{self.total_jobs})")
            
            # Print updated progress after each job completion
            self._print_progress()
    
    def _print_progress(self):
        """
        Print current progress statistics.
        
        Calculates and displays:
        - Progress percentage
        - Counts of completed, failed, and running jobs
        - Elapsed time
        - Estimated time to completion (ETA)
        """
        elapsed = time.time() - self.start_time
        # Calculate progress percentage based on completed + failed jobs
        progress = (self.completed_jobs + self.failed_jobs) / self.total_jobs * 100
        # Calculate ETA: average time per job * remaining jobs
        eta = (elapsed / (self.completed_jobs + self.failed_jobs)) * (self.total_jobs - self.completed_jobs - self.failed_jobs) if (self.completed_jobs + self.failed_jobs) > 0 else 0
        
        logger.info(f"📊 Progress: {progress:.1f}% | "
                   f"Completed: {self.completed_jobs} | "
                   f"Failed: {self.failed_jobs} | "
                   f"Running: {self.running_jobs} | "
                   f"Elapsed: {elapsed:.1f}s | "
                   f"ETA: {eta:.1f}s")

def generate_jobs(datasets: List[str], prompt_versions: List[str], models: List[str], cwes: List[str]) -> List[AnalysisJob]:
    """
    Generate all job combinations from input parameters.
    
    Creates a cartesian product of all input parameters:
    - For each dataset
    - For each prompt version
    - For each model
    - For each CWE
    
    Example: 1 dataset × 2 prompt versions × 3 models × 4 CWEs = 24 jobs
    
    Args:
        datasets: List of dataset names (e.g., ["owasp"])
        prompt_versions: List of prompt template versions (e.g., ["baseline", "optimized"])
        models: List of LLM model names (e.g., ["o4-mini", "google/gemini-2.5-pro"])
        cwes: List of CWE identifiers (e.g., ["CWE-078", "CWE-079"])
        
    Returns:
        List[AnalysisJob]: List of all job combinations to execute
    """
    jobs = []
    
    # Generate cartesian product of all parameters
    for dataset in datasets:
        for prompt_version in prompt_versions:
            for model in models:
                for cwe in cwes:
                    job = AnalysisJob(
                        dataset=dataset,
                        prompt_version=prompt_version,
                        model=model,
                        cwe=cwe
                    )
                    jobs.append(job)
    
    logger.info(f"Generated {len(jobs)} analysis jobs")
    return jobs

def get_owasp_paths(cwe: str) -> Dict[str, str]:
    """
    Get file paths required for OWASP dataset analysis.
    
    Returns paths to:
    - SARIF file: Static analysis results for the specific CWE
    - Source code root: OWASP Benchmark Java source code
    - Ground truth CSV: Expected results for evaluation
    
    Args:
        cwe: CWE identifier (e.g., "CWE-078", "CWE-079")
        
    Returns:
        dict: Dictionary with keys:
            - sarif_file: Path to SARIF results file
            - project_src_root: Path to source code directory
            - expected_results_csv: Path to ground truth CSV file
    """
    return {
        'sarif_file': f"input_files/sarif_results/owasp-benchmark/owasp-benchmark-{cwe}.sarif",
        'project_src_root': "input_files/source_code/BenchmarkJava",
        'expected_results_csv': "input_files/ground_truth/expectedresults-1.2.csv"
    }

def check_paths_exist(paths: Dict[str, str], dataset: str) -> bool:
    """
    Validate that all required file paths exist before running analysis.
    
    This prevents jobs from failing after starting due to missing files.
    Checks all paths in the paths dictionary and logs warnings for missing files.
    
    Args:
        paths: Dictionary of path names to file paths
        dataset: Dataset name (for logging purposes)
        
    Returns:
        bool: True if all paths exist, False if any path is missing
    """
    for key, path in paths.items():
        if not os.path.exists(path):
            logger.warning(f"Path does not exist for {dataset} {key}: {path}")
            return False
    return True

def run_owasp_analysis(job: AnalysisJob, paths: Dict[str, str], progress: ProgressTracker) -> bool:
    """
    Execute OWASP analysis for a single job by running analyze_with_llm.py as subprocess.
    
    This function:
    1. Builds the command to run analyze_with_llm.py with appropriate parameters
    2. Launches the subprocess and streams output in real-time
    3. Tracks job progress through ProgressTracker
    4. Handles errors and timeouts gracefully
    
    Args:
        job: AnalysisJob configuration for this analysis
        paths: Dictionary of file paths (SARIF, source code, ground truth)
        progress: ProgressTracker instance for status updates
        
    Returns:
        bool: True if analysis completed successfully, False otherwise
    """
    try:
        # Notify progress tracker that job has started
        progress.job_started(job.job_id)
        
        # Build command to run analyze_with_llm.py with all required parameters
        cmd = [
            'python', 'analyze_with_llm.py',
            '--sarif_file', paths['sarif_file'],
            '--project_src_root', paths['project_src_root'],
            '--expected_results_csv', paths['expected_results_csv'],
            '--model', job.model,
            '--prompt_version', job.prompt_version,
            '--enable_token_counting'  # Enable cost tracking
        ]
        
        logger.info(f"Running OWASP analysis: {' '.join(cmd)}")
        
        # Use Popen to get real-time output streaming
        # This allows us to see progress as the analysis runs
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,  # Capture stdout for logging
            stderr=subprocess.PIPE,  # Capture stderr for error reporting
            text=True,               # Return strings instead of bytes
            bufsize=1,               # Line buffered for real-time output
            universal_newlines=True
        )
        
        # Stream output in real-time to see progress
        stdout_lines = []
        stderr_lines = []
        
        # Read output line by line until process completes
        while True:
            stdout_line = process.stdout.readline()
            stderr_line = process.stderr.readline()
            
            # Log stdout lines with job ID prefix for identification
            if stdout_line:
                stdout_lines.append(stdout_line.strip())
                logger.info(f"[{job.job_id}] {stdout_line.strip()}")
            
            # Log stderr lines as warnings (may contain important info)
            if stderr_line:
                stderr_lines.append(stderr_line.strip())
                logger.warning(f"[{job.job_id}] {stderr_line.strip()}")
            
            # Check if process has finished (poll() returns returncode when done)
            if process.poll() is not None:
                break
        
        # Wait for process to complete and get return code
        returncode = process.wait()
        
        # Check if analysis succeeded (return code 0 = success)
        if returncode == 0:
            logger.info(f"OWASP analysis completed successfully for {job.job_id}")
            progress.job_completed(job.job_id, success=True)
            return True
        else:
            # Log error output for debugging
            stderr_output = '\n'.join(stderr_lines)
            logger.error(f"OWASP analysis failed for {job.job_id}: {stderr_output}")
            progress.job_completed(job.job_id, success=False)
            return False
            
    except subprocess.TimeoutExpired:
        # Handle timeout if subprocess takes too long
        logger.error(f"OWASP analysis timed out for {job.job_id}")
        progress.job_completed(job.job_id, success=False)
        return False
    except Exception as e:
        # Handle any other unexpected errors
        logger.error(f"OWASP analysis error for {job.job_id}: {e}")
        progress.job_completed(job.job_id, success=False)
        return False

def run_single_job(job: AnalysisJob, progress: ProgressTracker) -> bool:
    """
    Execute a single analysis job.
    
    This is the main entry point for running one analysis job. It:
    1. Determines which dataset is being analyzed
    2. Gets the required file paths for that dataset
    3. Validates that all paths exist
    4. Calls the appropriate analysis function
    
    Currently only supports OWASP dataset, but can be extended for other datasets.
    
    Args:
        job: AnalysisJob configuration to execute
        progress: ProgressTracker instance for status updates
        
    Returns:
        bool: True if job completed successfully, False otherwise
    """
    logger.info(f"Starting job: {job.job_id}")
    
    if job.dataset.lower() == 'owasp':
        # Get paths for OWASP dataset
        paths = get_owasp_paths(job.cwe)
        
        # Validate all required paths exist before starting
        if not check_paths_exist(paths, 'owasp'):
            logger.error(f"Required paths not found for OWASP CWE {job.cwe}")
            progress.job_completed(job.job_id, success=False)
            return False
        
        # Run the OWASP analysis
        return run_owasp_analysis(job, paths, progress)
    
    else:
        # Unknown dataset - log error and mark job as failed
        logger.error(f"Unknown dataset: {job.dataset}")
        progress.job_completed(job.job_id, success=False)
        return False

def main():
    """
    Main function: Parse arguments and orchestrate parallel analysis execution.
    
    This function:
    1. Parses command line arguments for datasets, models, CWEs, etc.
    2. Generates all job combinations (cartesian product)
    3. Optionally runs in dry-run mode to preview jobs
    4. Executes jobs in parallel using ThreadPoolExecutor
    5. Tracks progress and reports final statistics
    
    The script supports running multiple analysis jobs concurrently to reduce
    total execution time when analyzing multiple combinations of:
    - Datasets (currently OWASP)
    - Prompt template versions (baseline, optimized)
    - LLM models (various providers)
    - CWE categories
    """
    parser = argparse.ArgumentParser(
        description='Run parallel analysis jobs with direct command line parameters',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Medium test with OWASP dataset
  python run_parallel_analysis.py --datasets owasp --prompt-versions optimized --models o4-mini google/gemini-2.5-pro --cwes CWE-078 CWE-079 CWE-089 CWE-090 --threads 4

  # Dry run to see what would be executed
  python run_parallel_analysis.py --datasets owasp --prompt-versions optimized --models o4-mini --cwes CWE-078 --threads 2 --dry-run
        """
    )
    
    # Required arguments - must be provided by user
    parser.add_argument('--datasets', nargs='+', required=True, 
                       choices=['owasp'],
                       help='Datasets to analyze (currently only "owasp" supported)')
    parser.add_argument('--prompt-versions', nargs='+', required=True,
                       help='Prompt template versions to use (baseline, optimized, or both)')
    parser.add_argument('--models', nargs='+', required=True,
                       help='LLM models to use (e.g., o4-mini, google/gemini-2.5-pro, deepseek/deepseek-r1)')
    parser.add_argument('--cwes', nargs='+', required=True,
                       help='CWE identifiers to analyze (e.g., CWE-078, CWE-079, CWE-089)')
    
    # Optional arguments - have default values
    parser.add_argument('--threads', type=int, default=4,
                       help='Number of parallel threads for concurrent execution (default: 4)')
    parser.add_argument('--dry-run', action='store_true',
                       help='Preview jobs without executing them (useful for testing)')
    
    args = parser.parse_args()
    
    # Generate all job combinations from input parameters
    # This creates a cartesian product: dataset × prompt_version × model × cwe
    jobs = generate_jobs(args.datasets, args.prompt_versions, args.models, args.cwes)
    
    # Dry run mode: show what would be executed without actually running
    if args.dry_run:
        logger.info("DRY RUN - Would execute the following jobs:")
        for job in jobs:
            logger.info(f"  {job.job_id}")
        logger.info(f"Total: {len(jobs)} jobs with {args.threads} threads")
        return
    
    # Initialize progress tracker to monitor all jobs
    progress = ProgressTracker(len(jobs))
    
    # Log analysis configuration
    logger.info(f"Starting parallel analysis with {len(jobs)} jobs using {args.threads} threads")
    logger.info(f"Datasets: {args.datasets}")
    logger.info(f"Prompt versions: {args.prompt_versions}")
    logger.info(f"Models: {args.models}")
    logger.info(f"CWEs: {args.cwes}")
    logger.info(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Run jobs in parallel using ThreadPoolExecutor
    # This allows multiple analysis jobs to run concurrently, significantly
    # reducing total execution time compared to sequential execution
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        # Submit all jobs to the thread pool
        # Each job runs in its own thread, up to max_workers threads at once
        future_to_job = {executor.submit(run_single_job, job, progress): job for job in jobs}
        
        # Wait for jobs to complete as they finish (not necessarily in order)
        # as_completed() yields futures as they complete, allowing us to process
        # results as soon as they're available
        for future in as_completed(future_to_job):
            job = future_to_job[future]
            try:
                # Get the result (this will raise exception if job failed)
                success = future.result()
                if not success:
                    logger.warning(f"Job {job.job_id} completed with errors")
            except Exception as e:
                # Handle unexpected exceptions in job execution
                logger.error(f"Job {job.job_id} generated an exception: {e}")
                progress.job_completed(job.job_id, success=False)
    
    # Print final summary statistics
    logger.info(f"Analysis completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"Final results: {progress.completed_jobs} successful, {progress.failed_jobs} failed")

if __name__ == '__main__':
    main() 