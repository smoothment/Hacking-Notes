#!/usr/bin/env python3
import os
import re
import argparse
from pathlib import Path

def clean_markdown_content(content):
    """
    Clean unwanted characters from markdown content
    """
    # Fix â€™ (should be apostrophe)
    content = re.sub(r'â€™', "'", content)
    
    # Fix standalone ™ that should be apostrophe
    content = re.sub(r'™', "'", content)
    
    # Remove â€ characters (the first part of the broken encoding)
    content = re.sub(r'â€', '', content)
    
    # Remove Â characters that appear before backticks
    content = re.sub(r'Â\s*`', '`', content)
    
    # Remove Â characters that appear before spaces
    content = re.sub(r'Â\s+', ' ', content)
    
    # Remove standalone Â characters
    content = re.sub(r'Â', '', content)
    
    # Clean up any double spaces that might have been created
    content = re.sub(r'  +', ' ', content)
    
    return content

def process_file(file_path):
    """
    Process a single markdown file
    """
    try:
        # Read the file with UTF-8 encoding
        with open(file_path, 'r', encoding='utf-8') as file:
            original_content = file.read()
        
        # Clean the content
        cleaned_content = clean_markdown_content(original_content)
        
        # Only write back if changes were made
        if original_content != cleaned_content:
            with open(file_path, 'w', encoding='utf-8') as file:
                file.write(cleaned_content)
            print(f"✓ Cleaned: {file_path}")
            return True
        else:
            print(f"- No changes needed: {file_path}")
            return False
            
    except Exception as e:
        print(f"✗ Error processing {file_path}: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Clean unwanted Â characters from markdown files')
    parser.add_argument('path', nargs='?', default='.', help='Path to directory or file (default: current directory)')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be changed without making changes')
    
    args = parser.parse_args()
    
    path = Path(args.path)
    
    if path.is_file():
        # Process single file
        if path.suffix.lower() == '.md':
            if args.dry_run:
                with open(path, 'r', encoding='utf-8') as file:
                    content = file.read()
                cleaned = clean_markdown_content(content)
                if content != cleaned:
                    print(f"Would clean: {path}")
                else:
                    print(f"No changes needed: {path}")
            else:
                process_file(path)
        else:
            print(f"Error: {path} is not a markdown file")
    
    elif path.is_dir():
        # Process all markdown files in directory
        md_files = list(path.rglob('*.md'))
        
        if not md_files:
            print("No markdown files found in the specified directory")
            return
        
        print(f"Found {len(md_files)} markdown files")
        
        cleaned_count = 0
        
        for md_file in md_files:
            if args.dry_run:
                with open(md_file, 'r', encoding='utf-8') as file:
                    content = file.read()
                cleaned = clean_markdown_content(content)
                if content != cleaned:
                    print(f"Would clean: {md_file}")
                    cleaned_count += 1
                else:
                    print(f"No changes needed: {md_file}")
            else:
                if process_file(md_file):
                    cleaned_count += 1
        
        if args.dry_run:
            print(f"\nWould clean {cleaned_count} out of {len(md_files)} files")
        else:
            print(f"\nCleaned {cleaned_count} out of {len(md_files)} files")
    
    else:
        print(f"Error: {path} does not exist")

if __name__ == "__main__":
    main()