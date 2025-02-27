#!/usr/bin/env python3
import os
import argparse
import subprocess

def process_directory(directory, output_dir, chosen_key, recursive):
    for root, dirs, files in os.walk(directory):
        for file in files:
            input_path = os.path.join(root, file)
            rel_path = os.path.relpath(input_path, directory)
            output_path = os.path.join(output_dir, rel_path)
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            print(f"Processing: {input_path} -> {output_path}")
            subprocess.run(["python3", "deobScriptMulti.py", input_path, output_path, str(chosen_key)])
        
        if not recursive:
            break

def main():
    parser = argparse.ArgumentParser(description="Batch XOR deobfuscation script")
    parser.add_argument("directory", type=str, help="Directory containing files to process")
    parser.add_argument("output_dir", type=str, help="Output directory for deobfuscated files")
    parser.add_argument("-k", "--chosen_key", type=int, default=32, help="XOR key to use (default: 32)")
    parser.add_argument("-r", "--recursive", action="store_true", help="Process directories recursively")
    args = parser.parse_args()

    process_directory(args.directory, args.output_dir, args.chosen_key, args.recursive)

if __name__ == "__main__":
    main()