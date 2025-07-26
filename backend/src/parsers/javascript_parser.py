import json
import logging
from typing import Optional, List, Dict, Any

from src.models import Dependency

logger = logging.getLogger(__name__)

def parse_package_json(content: str) -> Optional[List[Dependency]]:
    """
    Parses the content of a package.json file to extract JavaScript dependencies.
    Handles both dependencies and devDependencies sections.
    """
    dependencies: List[Dependency] = []
    try:
        data = json.loads(content)
        
        def extract_deps_from_section(deps_dict: Dict[str, str]):
            if not deps_dict:
                return
            
            for package_name, version_specifier in deps_dict.items():
                current_version = version_specifier.lstrip('^~<=>')
                
                if current_version and not current_version.startswith("git+") \
                    and not current_version.startswith("file:") \
                    and not current_version.startswith("link:") \
                    and not current_version.startswith("npm:") \
                    and not current_version.startswith("http"):
                    dependencies.append(Dependency(
                        package=package_name,
                        current_version=current_version,
                        type="javascript"
                    ))
                else:
                    logging.warning(f"JavaScriptParser: Skipping non-standard dependency: {package_name} with version {version_specifier}")
        prod_deps = data.get("dependencies", {})
        extract_deps_from_section(prod_deps)
        
        dev_deps = data.get("devDependencies", {})
        extract_deps_from_section(dev_deps)
        
    except json.JSONDecodeError as e:
        logger.error(f"JavaScriptParser: Failed to parse package.json content: {e}", exc_info=True)
    
    except Exception as e:
        logger.error(f"JavaScriptParser: Unexpected error parsing package.json content: {e}", exc_info=True)
    
    return dependencies