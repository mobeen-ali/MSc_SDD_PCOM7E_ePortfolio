import os
import re

def natural_sort_key(s):
    """Helper to sort strings containing numbers naturally."""
    return [int(text) if text.isdigit() else text.lower() for text in re.split(r'(\d+)', s)]

def should_ignore(name):
    """Check if a file or directory should be ignored."""
    ignore_patterns = [
        '__pycache__',
        '.pytest_cache',
        '.coverage',
        '.git',
        '.vscode',
        '.idea',
        '.ipynb_checkpoints',
        'node_modules',
        '.venv',
        'venv',
        'env',
        '.env',
        '*.pyc',
        '*.pyo',
        '*.pyd',
        '.DS_Store',
        'Thumbs.db'
    ]
    
    for pattern in ignore_patterns:
        if pattern in name or name.endswith(pattern.replace('*', '')):
            return True
    return False

def generate_tree(start_path, prefix="", output_lines=None):
    if output_lines is None:
        output_lines = []

    entries = [
        e for e in os.listdir(start_path)
        if not e.startswith('.') and not should_ignore(e)  # ignore hidden files/folders and ignored patterns
    ]

    files = sorted(
        [f for f in entries if os.path.isfile(os.path.join(start_path, f))],
        key=natural_sort_key
    )
    dirs = sorted(
        [d for d in entries if os.path.isdir(os.path.join(start_path, d))],
        key=natural_sort_key
    )

    for index, directory in enumerate(dirs):
        is_last = index == len(dirs) - 1 and not files
        connector = "└── " if is_last else "├── "
        output_lines.append(f"{prefix}{connector}{directory}/")
        extension = "    " if is_last else "│   "
        generate_tree(os.path.join(start_path, directory), prefix + extension, output_lines)

    for index, file in enumerate(files):
        is_last = index == len(files) - 1
        connector = "└── " if is_last else "├── "
        output_lines.append(f"{prefix}{connector}{file}")

    return output_lines

if __name__ == "__main__":
    output_file = "folder_structure.txt"
    lines = ["."]
    lines.extend(generate_tree("."))

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"✅ Folder structure saved to '{output_file}'")
