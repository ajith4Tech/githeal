import re
from typing import List
from src.models import Dependency


def parse_requirements_txt(content: str):
    """
    Parses the content of a requirements.txt file to extract Python dependencies.
    Handles basic package==version and package>version syntax.
    """
    dependencies: List[Dependency] = []
    lines = content.split()
    for line in lines:
        line = line.strip()
        
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        package_regix = r"([a-zA-Z0-9._-]+)(?:(?:==|!=|<=|>=|<|>|~=)([a-zA-Z0-9._-]+(?:[abrc]\d+)?))?.*"
        match = re.match(package_regix, line)
        if match:
            package_name = match.group(1).strip()
            version_specifier = match.group(2)

            current_version = version_specifier if version_specifier else "unknown"
            
            dependencies.append(Dependency(package=package_name,
                                        current_version=current_version,
                                        type="python"))

        else:
            pass
    
    return dependencies