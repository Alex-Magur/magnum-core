import os

def safe_write_file(path: str, content: str) -> None:
    """
    Safely writes content to a file, ensuring the path is within /srv/dev-team.

    Args:
        path (str): The target file path.
        content (str): The content to write to the file.

    Raises:
        ValueError: If the path is outside of /srv/dev-team.
    """
    base_dir = os.path.abspath('/srv/dev-team')
    abs_path = os.path.abspath(path)

    # Check if the resolved path starts with the base directory path
    # We append os.sep to ensure we match directory boundaries,
    # unless the path is exactly the base directory (which is unlikely for a file write but strictly inside)
    # Actually, writing to the dir itself as a file would fail later, but for path check:

    if not abs_path.startswith(os.path.join(base_dir, '')):
        raise ValueError(f"Security Error: Cannot write to {path}. Access denied outside {base_dir}.")

    # Ensure directory exists
    os.makedirs(os.path.dirname(abs_path), exist_ok=True)

    with open(abs_path, 'w') as f:
        f.write(content)
