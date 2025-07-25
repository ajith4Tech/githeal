from pydantic import BaseModel
from typing import Optional, List

class Dependency(BaseModel):
    package: str
    current_version: str
    latest_version: Optional[str] = None
    type: str

class RepoUrl(BaseModel):
    repo_url: str

class AnalysisStatus(BaseModel):
    job_id: str
    status: str
    message: Optional[str] = None

class Vulnerability(BaseModel):
    package: str
    version: str
    vulnerability_id: str = "N/A"
    severity: str = "N/A"
    advisory_url: str = "N/A"

class MaintenanceStatus(BaseModel):
    package: str
    stars: Optional[int] = None
    forks: Optional[int] = None
    last_commit_date: Optional[str] = None
    open_issues: Optional[int] = None
    open_pull_requests: Optional[int] = None
    
    
class AnalysisReport(BaseModel):    
    repo_url: str
    total_dependencies: int = 0
    up_to_date_count: int = 0
    outdated_count: int = 0
    vulnerable_count: int = 0
    outdated_dependencies: List[Dependency] = []
    vulnerable_dependencies: List[Vulnerability] = []
    maintenance_status: List[MaintenanceStatus] = []