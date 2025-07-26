import logging
import os
import httpx
from typing import List, Dict, Any, Optional, Set, Tuple
from github import Github, GithubException
from github.Repository import Repository
from github.ContentFile import ContentFile
from packaging.version import parse as parse_version
import asyncio
import time
from asyncio_throttle import Throttler

from src.models import Dependency, Vulnerability, MaintenanceStatus
from src.parsers.python_parser import parse_requirements_txt
from src.parsers.javascript_parser import parse_package_json
from src.checkers.vulnerability_checker import aggregate_vulnerability_results, check_osv_vulnerabilities

logger = logging.getLogger(__name__)

PYPI_VERSION_CACHE: Dict[str, Dict[str, Any]] = {}
NPM_VERSION_CACHE: Dict[str, Dict[str, Any]] = {}
CACHE_EXPIRATION_SECONDS = 3600

# Throttlers - Using provided names
pypi_version_throttler = Throttler(rate_limit=10)
npm_version_throttler = Throttler(rate_limit=20)

MAX_RETRIES = 5
RETRY_DELAY_SECONDS = 3


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
    Fetches the latest stable version of a Python package from PyPI, using a cache and retries.
    """
    if package_name in PYPI_VERSION_CACHE:
        cached_data = PYPI_VERSION_CACHE[package_name]
        if (time.time() - cached_data["timestamp"]) < CACHE_EXPIRATION_SECONDS and cached_data["version"] is not None:
            logger.info(f"PyPI: Returning latest version for {package_name} from cache: {cached_data['version']}")
            return cached_data["version"]
        elif (time.time() - cached_data["timestamp"]) < CACHE_EXPIRATION_SECONDS and cached_data["version"] is None:
            logger.info(f"PyPI: Package {package_name} previously failed to fetch and is still in cache. Skipping retry for now.")
            return None
        else:
            logger.info(f"PyPI: Cache expired for {package_name}.")

    pypi_url = f"https://pypi.org/pypi/{package_name}/json"
    
    for attempt in range(MAX_RETRIES):
        async with pypi_version_throttler:
            async with httpx.AsyncClient() as client:
                try:
                    response = await client.get(pypi_url, timeout=15)
                    response.raise_for_status()
                    data = response.json()
                    
                    versions = [parse_version(v) for v in data["releases"].keys()]
                    stable_versions = [v for v in versions if not v.is_prerelease and not v.is_devrelease]
                    
                    latest_version_str = None
                    if stable_versions:
                        latest_stable = max(stable_versions)
                        latest_version_str = str(latest_stable)
                    elif versions:
                        latest_any = max(versions)
                        latest_version_str = str(latest_any)
                    
                    if latest_version_str:
                        logger.info(f"PyPI: Latest stable version for {package_name}: {latest_version_str} (Attempt {attempt + 1})")
                        PYPI_VERSION_CACHE[package_name] = {"version": latest_version_str, "timestamp": time.time()}
                        return latest_version_str
                    else:
                        logger.warning(f"PyPI: No versions found for package {package_name} (Attempt {attempt + 1})")
                        PYPI_VERSION_CACHE[package_name] = {"version": None, "timestamp": time.time()}
                        return None

                except httpx.HTTPStatusError as e:
                    if e.response.status_code == 404:
                        logger.warning(f"PyPI: Package '{package_name}' not found on PyPI (Status: 404, Attempt {attempt + 1}).")
                        PYPI_VERSION_CACHE[package_name] = {"version": None, "timestamp": time.time()}
                        return None
                    else:
                        logger.warning(f"PyPI: HTTP error fetching {package_name} (Status: {e.response.status_code}, Attempt {attempt + 1}): {e.response.text}")
                except httpx.RequestError as e:
                    logger.warning(f"PyPI: Network error fetching {package_name} (Attempt {attempt + 1}): {e}")
                except Exception as e:
                    logger.error(f"PyPI: Unexpected error processing PyPI data for {package_name} (Attempt {attempt + 1}): {e}", exc_info=True)
                    
                if attempt < MAX_RETRIES - 1:
                    logger.info(f"PyPI: Retrying {package_name} in {RETRY_DELAY_SECONDS} second(s)...")
                    await asyncio.sleep(RETRY_DELAY_SECONDS)
                else:
                    logger.error(f"PyPI: Failed to fetch {package_name} after {MAX_RETRIES} attempts.")
                    PYPI_VERSION_CACHE[package_name] = {"version": None, "timestamp": time.time()}
                    return None
    return None


async def get_latest_npm_version(package_name: str) -> Optional[str]:
    """
    Fetches the latest stable version of a JavaScript package from npm Registry, using a cache and retries.
    """
    if package_name in NPM_VERSION_CACHE:
        cached_data = NPM_VERSION_CACHE[package_name]
        if (time.time() - cached_data["timestamp"]) < CACHE_EXPIRATION_SECONDS and cached_data["version"] is not None:
            logger.info(f"npm: Returning latest version for {package_name} from cache: {cached_data['version']}")
            return cached_data["version"]
        elif (time.time() - cached_data["timestamp"]) < CACHE_EXPIRATION_SECONDS and cached_data["version"] is None:
            logger.info(f"npm: Package {package_name} previously failed to fetch and is still in cache. Skipping retry for now.")
            return None
        else:
            logger.info(f"npm: Cache expired for {package_name}.")

    npm_url = f"https://registry.npmjs.org/{package_name}"
    
    for attempt in range(MAX_RETRIES):
        async with npm_version_throttler: 
            async with httpx.AsyncClient() as client:
                try:
                    response = await client.get(npm_url, timeout=15)
                    response.raise_for_status()
                    data = response.json()
                    
                    latest_version_str = data.get("dist-tags", {}).get("latest")
                    
                    if latest_version_str:
                        logger.info(f"npm: Latest version for {package_name}: {latest_version_str} (Attempt {attempt + 1})")
                        NPM_VERSION_CACHE[package_name] = {"version": latest_version_str, "timestamp": time.time()}
                        return latest_version_str
                    else:
                        logger.warning(f"npm: No latest version found for package {package_name} (Attempt {attempt + 1}).")
                        NPM_VERSION_CACHE[package_name] = {"version": None, "timestamp": time.time()}
                        return None

                except httpx.HTTPStatusError as e:
                    if e.response.status_code == 404:
                        logger.warning(f"npm: Package '{package_name}' not found on npm Registry (Status: 404, Attempt {attempt + 1}).")
                        NPM_VERSION_CACHE[package_name] = {"version": None, "timestamp": time.time()}
                        return None
                    else:
                        logger.warning(f"npm: HTTP error fetching {package_name} (Status: {e.response.status_code}, Attempt {attempt + 1}): {e.response.text}")
                except httpx.RequestError as e:
                    logger.warning(f"npm: Network error fetching {package_name} (Attempt {attempt + 1}): {e}")
                except Exception as e:
                    logger.error(f"npm: Unexpected error processing npm data for {package_name} (Attempt {attempt + 1}): {e}", exc_info=True)
                    
                if attempt < MAX_RETRIES - 1:
                    logger.info(f"npm: Retrying {package_name} in {RETRY_DELAY_SECONDS} second(s)...")
                    await asyncio.sleep(RETRY_DELAY_SECONDS)
                else:
                    logger.error(f"npm: Failed to fetch {package_name} after {MAX_RETRIES} attempts.")
                    NPM_VERSION_CACHE[package_name] = {"version": None, "timestamp": time.time()}
                    return None
    return None
    

async def check_outdated_status(dep: Dependency) -> Optional[Dependency]:
    """ 
    Checks if a dependency is outdated based on its current and latest versions.
    """
    if dep.current_version == "unknown":
        logger.info(f"AnalysisService: Skipping outdated check for {dep.package} (version unknown).")
        return None
    
    latest_version_str = None
    if dep.type == "javascript":
        latest_version_str = await get_latest_npm_version(dep.package)
    elif dep.type == "python":
        latest_version_str = await get_latest_pypi_version(dep.package)
    else:
        logger.warning(f"AnalysisService: Skipping outdated check for unsupported dependency type: {dep.type}")
        return None

    if latest_version_str:
        current_ver = parse_version(dep.current_version)
        latest_ver = parse_version(latest_version_str)

        if latest_ver > current_ver:
            logger.info(f"AnalysisService: {dep.package} is outdated: {dep.current_version} -> {latest_version_str}")
            return Dependency(
                package=dep.package,
                current_version=dep.current_version,
                latest_version=latest_version_str,
                type=dep.type
            )
        else:
            logger.info(f"AnalysisService: {dep.package} is up to date: {dep.current_version} -> {latest_version_str}")
            return None
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

    combined_vulns = []
    if dep.type == "python":
        combined_vulns = await aggregate_vulnerability_results(dep.package, dep.current_version)
    elif dep.type == "javascript":
        # Placeholder for JS vulnerability check
        logger.info(f"AnalysisService: Skipping JS vulnerability check for {dep.package} (not yet implemented).")
        # TODO: Call npm-specific vulnerability checker (e.g., OSV.dev with ecosystem="npm")
        # combined_vulns = await check_npm_vulnerabilities(dep.package, dep.current_version)
        pass
    else:
        logger.warning(f"AnalysisService: Skipping vulnerability check for unsupported dependency type: {dep.type}")
        combined_vulns = []

    if combined_vulns:
        logger.warning(f"AnalysisService: {dep.package} ({dep.current_version}) has {len(combined_vulns)} vulnerabilities!")
    else:
        logger.info(f"AnalysisService: No vulnerabilities found for {dep.package} ({dep.current_version}).")
    return combined_vulns

async def process_manifest_file(
    content: str,
    file_name: str,
    lang_type: str
) -> Dict[str, Any]:
    """
    Parses a manifest file and performs outdated and vulnerability checks
    for the identified dependencies based on their language type.
    Returns a dictionary with the results.
    """
    
    dependencies: List[Dependency] = []
    outdated_dependencies: List[Dependency] = []
    vulnerable_dependencies: List[Vulnerability] = []
    vulnerable_pkgs_for_file: Set[str] = set()
    up_to_date_count = 0
    
    deps_to_process : List[Dependency] = []
    if lang_type == "python":
        logger.info(f"AnalysisService: Parsing {file_name} for Python dependencies...")
        deps_to_process = parse_requirements_txt(content)
    elif lang_type == "javascript":
        # Placeholder for future JavaScript parsing logic
        logger.info(f"AnalysisService: Parsing {file_name} for JavaScript dependencies (not implemented yet).")
        deps_to_process = parse_package_json(content)
    else:
        logger.warning(f"AnalysisService: Unsupported manifest type '{lang_type}' in file '{file_name}'. Skipping.")
        return {
            "dependencies": [],
            "outdated_dependencies": [],
            "up_to_date_count": 0,
            "vulnerable_dependencies": [],
            "vulnerable_count": 0,
            "maintenance_status": None
        }
    outdated_tasks = []
    vulnerability_tasks = []
    
    for dep in deps_to_process:
        dependencies.append(dep)
        outdated_tasks.append(check_outdated_status(dep))
        vulnerability_tasks.append(check_vulnerability_status(dep))
        
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
            
            if vulns_list_for_dep and vulns_list_for_dep[0].package:
                vulnerable_pkgs_for_file.add(vulns_list_for_dep[0].package)
    
    return {
        "dependencies": dependencies,
        "outdated_dependencies": outdated_dependencies,
        "vulnerable_dependencies": vulnerable_dependencies,
        "vulnerable_packages": list(vulnerable_pkgs_for_file),
        "vulnerable_count": len(vulnerable_pkgs_for_file),
        "up_to_date_count": up_to_date_count,
    }

async def analyze_repo_dependencies(
    github_client: Github,
    repo_owner: str,
    repo_name: str
) -> Dict[str, Any]:
    """
    Orchestrates the analysis of a GitHub repository's dependencies.
    """
    all_dependencies: List[Dependency] = []
    outdated_dependencies: List[Dependency] = []
    vulnerable_dependencies: List[Vulnerability] = []
    vulnerable_packages: Set[str] = set() # To count unique vulnerable packages across all files
    up_to_date_count = 0
    maintenance_status_list: List[MaintenanceStatus] = []

    try:
        repo = github_client.get_user(repo_owner).get_repo(repo_name)
        logger.info(f"AnalysisService: Accessed GitHub repository: {repo_owner}/{repo_name}")

        found_manifests = _fetch_all_manifest_files(repo)

        manifest_processing_tasks = []
        for file_path, manifest_data in found_manifests.items():
            content = manifest_data["content"]
            lang_type = manifest_data["type"]
            file_name = os.path.basename(file_path)
            
            manifest_processing_tasks.append(
                process_manifest_file(content, file_name, lang_type)
            )

        logger.info("AnalysisService: Processing all found manifest files concurrently...")
        if manifest_processing_tasks: # Only run if manifest files were found
            results_from_manifests = await asyncio.gather(*manifest_processing_tasks)

            for res in results_from_manifests:
                all_dependencies.extend(res.get("dependencies", []))
                outdated_dependencies.extend(res.get("outdated_dependencies", []))
                vulnerable_dependencies.extend(res.get("vulnerable_dependencies", []))
                vulnerable_packages.update(res.get("vulnerable_packages", set()))
                up_to_date_count += res.get("up_to_date_count", 0)


        return {
            "all_dependencies": all_dependencies,
            "outdated_dependencies": outdated_dependencies,
            "up_to_date_count": up_to_date_count,
            "outdated_count": len(outdated_dependencies),
            "vulnerable_dependencies": vulnerable_dependencies,
            "vulnerable_count": len(vulnerable_packages), # Count of unique vulnerable packages
            "maintenance_status": maintenance_status_list
        }

    except GithubException as e:
        logger.error(f"AnalysisService: GitHub API error in analyze_repo_dependencies: {e.data.get('message', str(e))}", exc_info=True)
        raise
    except Exception as e:
        logger.error(f"AnalysisService: Unexpected error in analyze_repo_dependencies: {e}", exc_info=True)
        raise