import re
from typing import Optional, Tuple

def parse_github_url(url:str):
    """
    Parses a GitHub URL and returns a tuple containing the owner and repository name.
    """
    match = re.match(r"https?://github.com/([^/]+)/([^/]+)(?:/.*)?", url)
    if match:
        owner = match.group(1)
        repo_name = match.group(2)
        if repo_name.endswith(".git"):
            repo_name = repo_name[:-4]
        return owner, repo_name
    return None