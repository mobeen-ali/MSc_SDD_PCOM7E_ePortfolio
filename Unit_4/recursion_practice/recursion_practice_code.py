import os

def recursive_list_files(path, depth=0, max_depth=5):
    """
    Recursively lists files and directories starting from the given path,
    indenting each level for clarity. Depth is limited to avoid infinite recursion.

    Args:
        path (str): The base directory to start scanning.
        depth (int): Current depth level in the directory tree (used internally).
        max_depth (int): Maximum allowed depth to prevent stack overflow.

    Returns:
        None
    """
    if depth > max_depth:
        print("  " * depth + f"[Max depth {max_depth} reached. Skipping deeper levels.]")
        return

    try:
        for entry in os.listdir(path):
            full_path = os.path.join(path, entry)
            if os.path.isdir(full_path):
                print("  " * depth + f"[DIR] {entry}/")
                recursive_list_files(full_path, depth + 1, max_depth)
            else:
                print("  " * depth + f"- {entry}")
    except PermissionError:
        print("  " * depth + f"[Access Denied] {path}")


if __name__ == "__main__":
    # Starting point for directory listing
    base_dir = os.getcwd()
    print("\n=== Directory File Listing ===")
    print(f"Starting from base directory: {base_dir}\n")
    recursive_list_files(base_dir)
    print("\n=== End of Directory Listing ===\n")