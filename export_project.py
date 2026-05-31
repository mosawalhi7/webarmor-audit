#!/usr/bin/env python3
"""
Project Exporter Utility
Generates a markdown file containing the folder structure and all file contents,
respecting .gitignore rules.
"""

import os
import subprocess
import re
import sys

def get_git_files(root_dir):
    """
    Attempts to list files using git ls-files.
    This is the most reliable way to respect .gitignore rules.
    """
    try:
        # Run git ls-files with cached and untracked files, excluding standard ignores
        result = subprocess.run(
            ['git', 'ls-files', '--cached', '--others', '--exclude-standard'],
            cwd=root_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        files = [f.strip() for f in result.stdout.splitlines() if f.strip()]
        # Convert path separators to forward slashes for consistency
        return sorted([f.replace('\\', '/') for f in files])
    except (subprocess.SubprocessError, FileNotFoundError):
        return None

def parse_gitignore(root_dir):
    """
    Parses the root .gitignore file as a fallback.
    """
    gitignore_path = os.path.join(root_dir, '.gitignore')
    if not os.path.exists(gitignore_path):
        return []
    
    rules = []
    try:
        with open(gitignore_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                rules.append(line)
    except Exception as e:
        print(f"Warning: Could not read .gitignore: {e}", file=sys.stderr)
    return rules

def compile_gitignore_rules(rules):
    """
    Compiles .gitignore glob patterns into regexes.
    """
    compiled_rules = []
    for rule in rules:
        is_negated = False
        if rule.startswith('!'):
            is_negated = True
            rule = rule[1:]
            
        # Treat trailing slash as folder matching
        is_dir_only = rule.endswith('/')
        if is_dir_only:
            rule = rule[:-1]
            
        # Escape regex special characters except glob symbols (*, ?, [)
        pattern = ""
        i = 0
        while i < len(rule):
            char = rule[i]
            if char == '*':
                if i + 1 < len(rule) and rule[i+1] == '*':
                    if i + 2 < len(rule) and rule[i+2] == '/':
                        pattern += '(?:.*/)?'
                        i += 3
                    else:
                        pattern += '.*'
                        i += 2
                else:
                    pattern += '[^/]*'
                    i += 1
            elif char == '?':
                pattern += '[^/]'
                i += 1
            elif char == '[':
                # Find matching bracket
                end_idx = rule.find(']', i)
                if end_idx != -1:
                    pattern += rule[i:end_idx+1]
                    i = end_idx + 1
                else:
                    pattern += '\\['
                    i += 1
            elif char in '.+^$()|{}':
                pattern += '\\' + char
                i += 1
            else:
                pattern += char
                i += 1
                
        # If pattern has no slash (excluding trailing), it matches anywhere
        if '/' not in rule:
            regex_str = f"^(?:.*/)?{pattern}"
        else:
            # If starts with /, match from root
            if rule.startswith('/'):
                regex_str = f"^{pattern[1:]}"
            else:
                regex_str = f"^{pattern}"
                
        if is_dir_only:
            regex_str += '(?:$|/)'
        else:
            regex_str += '(?:$|/.*)'
            
        try:
            compiled_rules.append((re.compile(regex_str), is_negated))
        except re.error:
            continue
            
    return compiled_rules

def is_ignored(path, compiled_rules):
    """
    Checks if a path matches compiled gitignore rules.
    """
    # Replace backslashes for standard matching
    path = path.replace('\\', '/')
    ignored = False
    for regex, is_negated in compiled_rules:
        if regex.search(path):
            ignored = not is_negated
    return ignored

def get_files_fallback(root_dir):
    """
    Fallback method to list files using os.walk and parsing .gitignore.
    """
    rules = parse_gitignore(root_dir)
    compiled_rules = compile_gitignore_rules(rules)
    
    # Always ignore common folders to prevent huge outputs
    default_ignores = [
        '.git', '__pycache__', '.venv', 'venv', 'env', 'node_modules',
        '.idea', '.vscode', 'build', 'dist', '.egg-info', '.DS_Store', 'Thumbs.db'
    ]
    
    files_list = []
    for root, dirs, files in os.walk(root_dir):
        # Calculate relative path from root
        rel_dir = os.path.relpath(root, root_dir)
        if rel_dir == '.':
            rel_dir = ""
            
        # Filter directories in place to prevent os.walk from descending into them
        filtered_dirs = []
        for d in dirs:
            rel_path = os.path.join(rel_dir, d).replace('\\', '/')
            # Check default ignores
            if d in default_ignores:
                continue
            # Check gitignore
            if is_ignored(rel_path + '/', compiled_rules):
                continue
            filtered_dirs.append(d)
        dirs[:] = filtered_dirs
        
        # Filter files
        for f in files:
            rel_path = os.path.join(rel_dir, f).replace('\\', '/')
            # Check default ignores
            if f in default_ignores:
                continue
            # Check gitignore
            if is_ignored(rel_path, compiled_rules):
                continue
            files_list.append(rel_path)
            
    return sorted(files_list)

def is_binary_file(file_path):
    """
    Checks if a file is binary by looking for null bytes in its first 1024 bytes.
    """
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
            return b'\x00' in chunk
    except Exception:
        return True

def generate_tree(paths):
    """
    Generates an ASCII folder tree structure from a list of relative paths.
    """
    tree = {}
    for p in paths:
        parts = p.split('/')
        current = tree
        for part in parts:
            current = current.setdefault(part, {})
            
    lines = []
    
    def walk(node, prefix=""):
        items = sorted(node.keys())
        for idx, item in enumerate(items):
            is_last = (idx == len(items) - 1)
            connector = "└── " if is_last else "├── "
            
            is_dir = len(node[item]) > 0
            display_name = item + "/" if is_dir else item
            
            lines.append(f"{prefix}{connector}{display_name}")
            
            if is_dir:
                next_prefix = prefix + ("    " if is_last else "│   ")
                walk(node[item], next_prefix)
                
    walk(tree)
    return "\n".join(lines)

def main():
    root_dir = os.path.abspath(os.path.dirname(__file__) or '.')
    output_filename = "project_context.md"
    script_filename = os.path.basename(__file__)
    
    print("🔍 Scanning project files...")
    
    # Try Git first
    files = get_git_files(root_dir)
    method = "Git ls-files"
    
    # Fallback to manual scanner
    if files is None:
        files = get_files_fallback(root_dir)
        method = "Directory Walk (Fallback with .gitignore parsing)"
        
    # Exclude the script itself and the output file
    files = [f for f in files if f != script_filename and f != output_filename]
    
    if not files:
        print("❌ No files found to export!")
        return
        
    print(f"✅ Found {len(files)} files using {method}.")
    
    # Generate tree
    print("🌳 Generating directory tree...")
    tree_str = generate_tree(files)
    
    # Write to output file
    output_path = os.path.join(root_dir, output_filename)
    print(f"📝 Writing to {output_filename}...")
    
    try:
        with open(output_path, 'w', encoding='utf-8') as out:
            out.write("# 📂 Project Context\n\n")
            out.write("This file contains the directory structure and contents of the files in the project.\n\n")
            
            out.write("## 🌳 Directory Tree\n\n")
            out.write("```\n")
            out.write(".\n")
            out.write(tree_str + "\n")
            out.write("```\n\n")
            
            out.write("---\n\n")
            out.write("## 📄 File Contents\n\n")
            
            for file_rel in files:
                file_abs = os.path.join(root_dir, file_rel)
                
                out.write(f"### 📄 `{file_rel}`\n\n")
                
                if is_binary_file(file_abs):
                    out.write("*[Binary file - Content omitted]*\n\n")
                    continue
                    
                # Determine language for markdown code blocks
                _, ext = os.path.splitext(file_rel)
                lang = ext[1:] if ext else ""
                # Map common extensions
                lang_mapping = {
                    'py': 'python',
                    'md': 'markdown',
                    'txt': 'text',
                    'js': 'javascript',
                    'ts': 'typescript',
                    'json': 'json',
                    'yml': 'yaml',
                    'yaml': 'yaml',
                    'toml': 'toml',
                    'ini': 'ini',
                    'cfg': 'ini',
                    'html': 'html',
                    'css': 'css',
                    'sh': 'bash',
                    'bat': 'batch',
                    'ps1': 'powershell'
                }
                lang_code = lang_mapping.get(lang.lower(), lang)
                
                out.write(f"```{lang_code}\n")
                try:
                    with open(file_abs, 'r', encoding='utf-8', errors='replace') as f:
                        out.write(f.read())
                except Exception as e:
                    out.write(f"[Error reading file: {str(e)}]")
                out.write("\n```\n\n")
                
        print(f"🎉 Success! The project has been exported to: {output_path}")
        print("You can now share this file with any AI model.")
        
    except Exception as e:
        print(f"❌ Error writing output file: {e}")

if __name__ == "__main__":
    main()
