import os


def recursive_list_files(path, depth=0, max_depth=5):
    """
    Recursively lists files up to a maximum directory depth.
    Prevents stack overflow by limiting recursion depth.
    """
    if depth > max_depth:
        return

    try:
        for entry in os.listdir(path):
            full_path = os.path.join(path, entry)
            if os.path.isdir(full_path):
                recursive_list_files(full_path, depth + 1, max_depth)
            else:
                print("  " * depth + f"- {entry}")
    except PermissionError:
        print("  " * depth + "[Access Denied]")


if __name__ == "__main__":
    base_dir = os.getcwd()  # Start in current working directory
    print(f"Listing files in: {base_dir}")
    recursive_list_files(base_dir)

