#!/usr/bin/env python3
"""
Script to clone projects and prepare src.zip for OpenVuln analysis.
Reads Projects_info.csv and for each project:
1. Clones the GitHub repository
2. Checkouts to the buggy commit
3. Creates the required directory structure
4. Zips it as src.zip in the appropriate location
"""

import csv
import os
import subprocess
import shutil
from pathlib import Path


def run_command(cmd, cwd=None, check=True):
    """Run a shell command and return the result."""
    print(f"  Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"  Error: {result.stderr}")
        raise Exception(f"Command failed: {' '.join(cmd)}")
    return result


def clone_and_prepare_project(project_info, base_dir="source_code", output_dir="sarif-files"):
    """Clone a project and prepare src.zip."""
    project_slug = project_info['project_slug']
    github_url = project_info['github_url']
    buggy_commit = project_info['buggy_commit_id']
    
    print(f"\n{'='*60}")
    print(f"Processing: {project_slug}")
    print(f"{'='*60}")
    
    # Create base directory for cloned repos
    os.makedirs(base_dir, exist_ok=True)
    
    # Extract repo name from URL (e.g., "spark" from "https://github.com/perwendel/spark")
    repo_name = github_url.rstrip('/').split('/')[-1]
    clone_path = os.path.join(base_dir, repo_name)
    
    # Step 1: Clone repository (or use existing)
    if os.path.exists(clone_path):
        print(f"Repository already exists at {clone_path}, using existing...")
    else:
        print(f"Cloning {github_url}...")
        run_command(["git", "clone", github_url, clone_path])
    
    # Step 2: Checkout buggy commit
    print(f"Checking out commit {buggy_commit}...")
    run_command(["git", "checkout", buggy_commit], cwd=clone_path)
    
    # Step 3: Create directory structure for src.zip
    # Structure: root/cwe-bench-java/project-sources/{project_slug}/
    temp_dir = os.path.join(base_dir, f"temp_{project_slug}")
    source_structure = os.path.join(temp_dir, "root", "cwe-bench-java", "project-sources", project_slug)
    
    # Clean up if exists
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
    
    os.makedirs(source_structure, exist_ok=True)
    
    print(f"Copying source files to {source_structure}...")
    # Copy all files except .git directory
    for item in os.listdir(clone_path):
        if item == '.git':
            continue
        src = os.path.join(clone_path, item)
        dst = os.path.join(source_structure, item)
        if os.path.isdir(src):
            shutil.copytree(src, dst, symlinks=False, ignore=shutil.ignore_patterns('.git'))
        else:
            shutil.copy2(src, dst)
    
    # Step 4: Create src.zip
    print(f"Creating src.zip...")
    zip_base = os.path.join(temp_dir, "src")
    shutil.make_archive(zip_base, 'zip', temp_dir, 'root')
    
    # Step 5: Move src.zip to output directory
    output_project_dir = os.path.join(output_dir, project_slug)
    os.makedirs(output_project_dir, exist_ok=True)
    
    src_zip_dest = os.path.join(output_project_dir, "src.zip")
    shutil.move(f"{zip_base}.zip", src_zip_dest)
    
    print(f"✓ Created {src_zip_dest}")
    
    # Clean up temp directory
    shutil.rmtree(temp_dir)
    
    print(f"✓ Successfully prepared {project_slug}")


def main():
    """Read Projects_info.csv and process all projects."""
    csv_file = "Projects_info.csv"
    
    if not os.path.exists(csv_file):
        print(f"Error: {csv_file} not found!")
        return
    
    # Read CSV
    projects = []
    with open(csv_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            projects.append(row)
    
    print(f"Found {len(projects)} projects in {csv_file}")
    
    # Process each project
    successful = 0
    failed = 0
    
    for project in projects:
        try:
            clone_and_prepare_project(project)
            successful += 1
        except Exception as e:
            print(f"✗ Failed to process {project['project_slug']}: {e}")
            failed += 1
    
    print(f"\n{'='*60}")
    print(f"Summary:")
    print(f"  Successful: {successful}/{len(projects)}")
    print(f"  Failed: {failed}/{len(projects)}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
