import os
import uuid
import logging
import asyncio
import shutil
import tempfile
from dotenv import load_dotenv

from fastapi import FastAPI, HTTPException, BackgroundTasks
from github import Github, GithubException
from typing import List, Optional, Dict, Any

from src.models import *
from src.github_utils import parse_github_url
from src.parsers.python_parser import parse_requirements_txt
from src.services.analysis_service import analyze_repo_dependencies
from src.services.github_service import get_github_rep_metadata
from fastapi.middleware.cors import CORSMiddleware

load_dotenv()
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s:%(name)s:%(message)s'
)
logger = logging.getLogger(__name__)


app = FastAPI(
    title="GitHeal",
    description="Actionable health analytics for any public GitHub repository: outdated dependencies, security vulnerabilities, and project maintenance insights.",
    version="0.1.0",
)

analysis_jobs: Dict[str, Dict[str, Any]] = {}

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
if not GITHUB_TOKEN:
    logger.warning("GITHUB_TOKEN environment variable not set. GitHub API rate limits might be hit for unauthenticated requests.")
    
github_client = Github(GITHUB_TOKEN) if GITHUB_TOKEN else Github()


async def perform_analysis(job_id: str, repo_owner: str, repo_name: str):
    """
    Performs the core repository analysis in a background task.
    Fetches repo contents, parses dependencies, checks for outdated versions and vulnerabilities.
    """
    logger.info(f"Performing analysis for job_id: {job_id}: {repo_owner}/{repo_name}")
    analysis_jobs[job_id]["status"] = "processing"
    analysis_jobs[job_id]["message"] = "Analysis in progress..."

    repo_temp_dir = None
    try:
        repo_temp_dir = tempfile.mkdtemp()
        logger.info(f"Created temporary directory: {repo_temp_dir}")
        
        try:
            main_repo_maintenance_status = await get_github_rep_metadata(
                github_client=github_client,
                repo_owner=repo_owner,
                repo_name=repo_name
            )
            if not main_repo_maintenance_status:
                logger.warning(f"Failed to fetch maintenance status for {repo_owner}/{repo_name}")
        
        except Exception as e:
            logger.error(f"Error fetching maintenance status for {repo_owner}/{repo_name}: {e}", exc_info=True)
        
        
        analysis_results = await analyze_repo_dependencies(
            github_client=github_client,
            repo_owner=repo_owner,
            repo_name=repo_name
        )
        
        all_dependencies = analysis_results.get("all_dependencies", [])
        outdated_dependencies = analysis_results.get("outdated_dependencies", [])
        up_to_date_count = analysis_results.get("up_to_date_count", 0)
        outdated_count = analysis_results.get("outdated_count", 0)
        vulnerable_dependencies = analysis_results.get("vulnerable_dependencies", [])
        vulnerable_count = analysis_results.get("vulnerable_count", 0)
        
        report = AnalysisReport(
            repo_url=f"https://github.com/{repo_owner}/{repo_name}",
            total_dependencies=len(all_dependencies),
            up_to_date_count = up_to_date_count,
            outdated_count = outdated_count,
            vulnerable_count = vulnerable_count,
            outdated_dependencies=outdated_dependencies,
            vulnerable_dependencies=vulnerable_dependencies,
            maintenance_status=[main_repo_maintenance_status] if main_repo_maintenance_status else []
        )
        analysis_jobs[job_id]["report"] = report
        analysis_jobs[job_id]["status"] = "completed"
        analysis_jobs[job_id]["message"] = "Analysis completed successfully!"
        logger.info(f"Job {job_id} completed for {repo_owner}/{repo_name}")
        logger.info(f"Final Report for Job {job_id}:\n{report.model_dump_json(indent=2)}")
    
    except GithubException as e:
        logger.error(f"Analysis failed for job_id: {job_id}: {e}", exc_info=True)
        analysis_jobs[job_id]["status"] = "failed"
        analysis_jobs[job_id]["message"] = f"GitHub API error: {e.data.get('message', str(e))}"
    
    except Exception as e:
        logger.error(f"Analysis failed for job_id: {job_id}: {e}", exc_info=True)
        analysis_jobs[job_id]["status"] = "failed"
        analysis_jobs[job_id]["message"] = f"Analysis failed: {str(e)}"
    
    finally:
        if repo_temp_dir and os.path.exists(repo_temp_dir):
            shutil.rmtree(repo_temp_dir)
            logger.info(f"Cleaned up temporary directory: {repo_temp_dir}")


@app.get("/")
async def root():
    """
    Root endpoint for the API.
    """
    return {"message": "Welcome to GitHeal!"}

@app.get("/health")
async def health():
    """
    Health check endpoint to verify API status.
    """
    return {"status": "ok", "service": "GitHeal"}


@app.post("/analyze", response_model=AnalysisStatus)
async def analyze_repo(repo_url_data: RepoUrl, background_tasks: BackgroundTasks):
    """
    Initiates an asynchronous dependency health analysis for a given GitHub repository.
    Returns a job ID to track the analysis status.
    """
    repo_info = parse_github_url(repo_url_data.repo_url)
    if not repo_info:
        raise HTTPException(status_code=400, detail="Invalid GitHub URL provided.")
    
    repo_owner, repo_name = repo_info
    job_id = str(uuid.uuid4())
    
    analysis_jobs[job_id] = {
        "status": "pending",
        "message" : "Analysis queued",
        "repo_url": repo_url_data.repo_url,
        "report": None
    }
    
    background_tasks.add_task(perform_analysis, job_id, repo_owner, repo_name)
    
    return AnalysisStatus(job_id=job_id, status="pending", message="Analysis started")

@app.get("/status/{job_id}", response_model=AnalysisStatus)
async def get_analysis_status(job_id: str):
    """
    Checks the current status of a previously initiated analysis job.
    """
    job = analysis_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    
    logger.info(f"Status requested for job {job_id}: current status is '{job['status']}'")
    return AnalysisStatus(job_id=job_id, status=job["status"], message=job["message"])

@app.get("/report/{job_id}", response_model=AnalysisReport)
async def get_analysis_report(job_id: str):
    """
    Retrieves the full analysis report for a completed job.
    """
    job = analysis_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    
    if job["status"] != "completed":
        raise HTTPException(status_code=400, detail=f"Analysis for job '{job_id}' is '{job['status']}'. Please wait for completion.")
    
    if not job["report"]:
        raise HTTPException(status_code=500, detail=f"No report available for job {job_id}. Internal server error.")
    
    logger.info(f"Report requested for job {job_id}")
    return job["report"]
    
    
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)