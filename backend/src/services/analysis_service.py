import logging
import time
import os
import httpx
from typing import List, Dict, Any, Optional, Set
from github import Github, GithubException
from github.Repository import Repository
from github.ContentFile import ContentFile
from packaging.version import parse as parse_version
import asyncio

from src.models import Dependency, Vulnerability, MaintenanceStatus
from src.parsers.python_parser import parse_requirements_txt
from src.checkers.vulnerability_checker import aggregate_vulnerability_results


logger = logging.getLogger(__name__)

PYPI_VERSION_CACHE: Dict[str, Dict[str, Any]] = {}
CACHE_EXPIRATION_SECONDS = 3600  # 1 hour





# Standardized global constant for manifest file types.
MANIFEST_FILE_TYPES = {
    "requirements.txt": "python",
    "package.json": "javascript",
    "pyproject.toml": "python",
    "pom.xml": "java",
    "Gemfile": "ruby",
    "go.mod": "go",
}


def _fetch_all_manifest_files(
    repo: Repository,
    path: str = "",
    max_depth: int = 2
) -> Dict[str, Dict[str, str]]:
    """
    Recursively searches a GitHub repository for predefined manifest files.
    Returns a dictionary of {full_file_path: {content: "...", type: "language"}}.
    """
    found_manifests: Dict[str, Dict[str, str]] = {}
    current_depth = path.count('/')

    try:
        contents = repo.get_contents(path)
        if not isinstance(contents, list):
            contents = [contents]

        for content_file in contents:
            if content_file.type == "dir":
                if current_depth < max_depth:
                    logger.debug(f"AnalysisService: Searching directory: {content_file.path} (Depth: {current_depth+1})")
                    found_manifests.update(_fetch_all_manifest_files(repo, content_file.path, max_depth))
                else:
                    logger.info(f"AnalysisService: Max recursion depth ({max_depth}) reached for directory: {content_file.path}. Skipping deeper search.")
            elif content_file.type == "file":
                file_name = content_file.name
                if file_name in MANIFEST_FILE_TYPES:
                    try:
                        content = content_file.decoded_content.decode('utf-8')
                        found_manifests[content_file.path] = {
                            "content": content,
                            "type": MANIFEST_FILE_TYPES[file_name]
                        }
                        logger.info(f"AnalysisService: Found and fetched manifest file: {content_file.path}")
                    except Exception as e:
                        logger.error(f"AnalysisService: Error decoding content of {content_file.path}: {e}", exc_info=True)
            else:
                 logger.debug(f"AnalysisService: Skipping non-file/non-directory content type: {content_file.path} (type: {content_file.type})")
    except GithubException as e:
        if e.status == 404:
            logger.debug(f"AnalysisService: Path '{path}' not found in repo (404).")
        else:
            logger.error(f"AnalysisService: GitHub API error fetching contents for '{path}': {e.data.get('message', str(e))}", exc_info=True)
            raise

    return found_manifests


async def get_latest_pypi_version(package_name: str) -> Optional[str]:
    """
    Fetches the latest stable version of a Python package from PyPI.
    """
    pypi_url = f"https://pypi.org/pypi/{package_name}/json"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(pypi_url, timeout=10)
            response.raise_for_status()
            data = response.json()
            versions = [parse_version(v) for v in data["releases"].keys()]
            stable_versions = [v for v in versions if not v.is_prerelease and not v.is_devrelease]
            if stable_versions:
                latest_stable = max(stable_versions)
                latest_version_str = str(latest_stable)
                logger.info(f"PyPI: Latest stable version for {package_name}: {latest_version_str}")
                
                PYPI_VERSION_CACHE[package_name] = {
                    "version": latest_version_str,
                    "timestamp": time.time()
                }
                
                return latest_version_str
            else:
                if versions:
                    latest_any = max(versions)
                    latest_version_str = str(latest_any)
                    logger.info(f"PyPI: Only pre-releases found for {package_name}. Latest: {latest_any}")
                    
                    PYPI_VERSION_CACHE[package_name] = {
                    "version": latest_version_str,
                    "timestamp": time.time()
                    }
                    
                    
                    return latest_version_str
                logger.warning(f"PyPI: No versions found for package {package_name}")
                return None
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                logger.warning(f"PyPI: Package '{package_name}' not found on PyPI. Status: {e.response.status_code}")
            else:
                logger.error(f"PyPI: HTTP error fetching {package_name} from PyPI: {e.response.status_code} - {e.response.text}", exc_info=True)
            return None
        except httpx.RequestError as e:
            logger.error(f"PyPI: Network error fetching {package_name} from PyPI: {e}", exc_info=True)
            return None
        except Exception as e:
            logger.error(f"PyPI: Unexpected error processing PyPI data for {package_name}: {e}", exc_info=True)
            return None


async def analyze_repo_dependencies(
    github_client: Github,
    repo_owner: str,
    repo_name: str
) -> Dict[str, Any]:
    """
    Orchestrates the analysis of a GitHub repository's dependencies.
    This function coordinates fetching, parsing, and applying various checks
    (outdated, vulnerabilities) to identified dependencies.
    """
    
    all_dependencies: List[Dependency] = []
    
    outdated_tasks = []
    vulnerability_tasks = []
    
    
    
    outdated_dependencies: List[Dependency] = []
    vulnerable_dependencies: List[Vulnerability] = []
    vulnerable_packages: Set[str] = set() # To count unique vulnerable packages
    up_to_date_count = 0

    try:
        repo = github_client.get_user(repo_owner).get_repo(repo_name)
        logger.info(f"AnalysisService: Accessed GitHub repository: {repo_owner}/{repo_name}")

        # 1. Fetch all relevant manifest files from the repository
        found_manifests = _fetch_all_manifest_files(repo)

        # 2. Process Found Manifest Files (currently focusing on Python)
        for file_path, manifest_data in found_manifests.items():
            content = manifest_data["content"]
            lang_type = manifest_data["type"]
            file_name = os.path.basename(file_path)

            if file_name == "requirements.txt" and lang_type == "python":
                logger.info(f"AnalysisService: Parsing requirements.txt at '{file_path}'...")
                python_deps = parse_requirements_txt(content)

                # Iterate through each parsed Python dependency and run checks
                for dep in python_deps:
                    all_dependencies.append(dep) # Add to the overall list of dependencies
                    
                    outdated_tasks.append(check_outdated_status(dep))
                    if dep.current_version != "unknown":
                        vulnerability_tasks.append(check_vulnerability_status(dep))
                    
                    else:
                        logger.info(f"AnalysisService: Skipping vulnerability check for {dep.package} (version unknown).")
                        vulnerability_tasks.append(asyncio.sleep(0, result=[]))                    
            
            elif file_name == "package.json" and lang_type == "javascript":
                logger.info(f"AnalysisService: Parsing package.json at '{file_path}' (placeholder for future step)...")
                pass
            else:
                logger.debug(f"AnalysisService: Skipping unhandled manifest type or file: {file_path} ({lang_type})")

        logger.info("AnalysisService: Running All Outdated and Vulnerability checks concurrently...")
        outdated_results, vulnerability_results = await asyncio.gather(
            asyncio.gather(*outdated_tasks),
            asyncio.gather(*vulnerability_tasks)
        )
        
        for result in outdated_results:
            if result:
                outdated_dependencies.append(result)
            else:
                up_to_date_count += 1
        
        for vulns_list_for_dep in vulnerability_results:
            if vulns_list_for_dep:
                vulnerable_dependencies.extend(vulns_list_for_dep)
                vulnerable_packages.add(vulns_list_for_dep[0].package)
        
        # Compile and return all collected analysis data
        return {
            "all_dependencies": all_dependencies,
            "outdated_dependencies": outdated_dependencies,
            "up_to_date_count": up_to_date_count,
            "outdated_count": len(outdated_dependencies),
            "vulnerable_dependencies": vulnerable_dependencies,
            "vulnerable_count": len(vulnerable_packages),
            "maintenance_status": None    # Count of unique vulnerable packages
        }

    except GithubException as e:
        logger.error(f"AnalysisService: GitHub API error in analyze_repo_dependencies: {e.data.get('message', str(e))}", exc_info=True)
        raise
    except Exception as e:
        logger.error(f"AnalysisService: Unexpected error in analyze_repo_dependencies: {e}", exc_info=True)
        raise

async def check_outdated_status(dep: Dependency) -> Optional[Dependency]:
    """ 
    Checks if a dependency is outdated based on its current and latest versions.
    """
    if dep.current_version == "unknown":
        logger.info(f"AnalysisService: Skipping outdated check for {dep.package} (version unknown).")
        return None # Not outdated, but not definitively up-to-date either
    
    latest_version_str = await get_latest_pypi_version(dep.package)
    if latest_version_str:
        current_ver = parse_version(dep.current_version)
        latest_ver = parse_version(latest_version_str)

        if latest_ver > current_ver:
            logger.info(f"AnalysisService: {dep.package} is outdated: {dep.current_version} -> {latest_version_str}")
            return Dependency(
                package=dep.package,
                current_version=dep.current_version,
                latest_version=latest_version_str,
                type="python"
            )
        else:
            logger.info(f"AnalysisService: {dep.package} is up to date: {dep.current_version} -> {latest_version_str}")
            return None # Not outdated
    else:
        logger.warning(f"AnalysisService: Unable to fetch latest version for {dep.package}. Skipping outdated check.")
        return None
    
async def check_vulnerability_status(dep: Dependency) -> List[Vulnerability]:
    """
    Checks for known vulnerabilities in a given dependency using aggregated sources.
    Returns a list of Vulnerability objects if found, an empty list otherwise.
    """
    if dep.current_version == "unknown":
        logger.info(f"AnalysisService: Skipping vulnerability check with unknown version: {dep.package}")
        return []

    combined_vulns = await aggregate_vulnerability_results(dep.package, dep.current_version)
    if combined_vulns:
        logger.warning(f"AnalysisService: {dep.package} ({dep.current_version}) has {len(combined_vulns)} vulnerabilities!")
    else:
        logger.info(f"AnalysisService: No vulnerabilities found for {dep.package} ({dep.current_version}).")
    return combined_vulns