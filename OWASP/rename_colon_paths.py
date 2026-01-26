#!/usr/bin/env python3
"""
Script to rename directories and files containing 'cliproxy:gemini-2.5-pro' 
to use 'cliproxy-gemini-2.5-pro' instead (replacing : with -)

This fixes Windows compatibility issues where colons are not allowed in filenames.
"""

import os
import shutil
from pathlib import Path


def rename_paths_with_colon(base_dir):
    """
    Recursively rename directories and files containing colons.
    
    Args:
        base_dir: Base directory to start renaming from
    """
    base_path = Path(base_dir)
    
    if not base_path.exists():
        print(f"Directory {base_dir} not found!")
        return
    
    # First, collect all paths that need renaming (to avoid renaming while iterating)
    # We need to process directories first (top-down) to avoid path issues
    paths_to_rename = []
    
    # Walk through all directories and files
    # We need to process from deepest to shallowest for directories
    all_dirs = []
    all_files = []
    
    for root, dirs, files in os.walk(base_path, topdown=False):  # bottom-up to rename deepest first
        root_path = Path(root)
        
        # Check directories
        for d in dirs:
            if ':' in d:
                old_path = root_path / d
                new_name = d.replace(':', '-')
                new_path = root_path / new_name
                all_dirs.append(('dir', old_path, new_path))
        
        # Check files
        for f in files:
            if ':' in f:
                old_path = root_path / f
                new_name = f.replace(':', '-')
                new_path = root_path / new_name
                all_files.append(('file', old_path, new_path))
    
    # Process directories first (deepest to shallowest)
    paths_to_rename = all_dirs + all_files
    
    if not paths_to_rename:
        print("No paths with colons found to rename.")
        return
    
    print(f"Found {len(paths_to_rename)} paths to rename:")
    print(f"  - {len(all_dirs)} directories")
    print(f"  - {len(all_files)} files")
    print()
    
    # Now rename them
    renamed_count = 0
    for path_type, old_path, new_path in paths_to_rename:
        try:
            if not old_path.exists():
                print(f"⚠️  Warning: Path does not exist: {old_path}")
                continue
                
            if new_path.exists():
                print(f"⚠️  Warning: Target already exists: {new_path}")
                continue
            
            if path_type == 'dir':
                print(f"Renaming directory: {old_path} -> {new_path}")
                shutil.move(str(old_path), str(new_path))
            else:
                print(f"Renaming file: {old_path} -> {new_path}")
                old_path.rename(new_path)
            
            renamed_count += 1
        except Exception as e:
            print(f"❌ Error renaming {old_path}: {e}")
    
    print(f"\n✅ Successfully renamed {renamed_count}/{len(paths_to_rename)} paths")


if __name__ == '__main__':
    results_dir = "results"
    if os.path.exists(results_dir):
        print(f"Renaming paths containing colons in {results_dir}...")
        print("=" * 60)
        rename_paths_with_colon(results_dir)
        print("=" * 60)
        print("Done!")
    else:
        print(f"Directory {results_dir} not found!")
        print("Make sure you run this script from the OWASP directory.")

