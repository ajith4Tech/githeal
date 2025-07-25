import logging
from typing import Optional, Tuple
from github import Github, GithubException
from src.models import MaintenanceStatus
from src.github_utils import parse_github_url

logger = logging.getLogger(__name__)

async def get_github_rep_metadata(
    github_client: Github,
    repo_owner: str,
    repo_name: str
) -> Optional[MaintenanceStatus]:
    """
    Fetches metadata for a GitHub repository.
    """
    try:
        repo = github_client.get_user(repo_owner).get_repo(repo_name)
        stars = repo.stargazers_count
        forks = repo.forks_count
        open_issues = repo.open_issues_count
        last_commit_date = None
        open_pull_requests = None

        # Fetch last commit date
        try:
            commits = repo.get_commits()
            if commits.totalCount > 0:
                last_commit = commits[0]
                last_commit_date = last_commit.commit.author.date.isoformat()
        except GithubException as e:
            logger.warning(f"GitHubService: Could not fetch last commit for {repo_owner}/{repo_name}: {e.data.get('message', str(e))}")
        except Exception as e:
            logger.warning(f"GitHubService: Unexpected error fetching last commit for {repo_owner}/{repo_name}: {e}", exc_info=True)

        # Fetch open pull requests count
        try:
            open_pull_requests = repo.get_pulls(state="open").totalCount
        except GithubException as e:
            logger.warning(f"GitHubService: Could not fetch open pull requests for {repo_owner}/{repo_name}: {e.data.get('message', str(e))}")
        except Exception as e:
            logger.warning(f"GitHubService: Unexpected error fetching open PRs for {repo_owner}/{repo_name}: {e}", exc_info=True)

        logger.info(f"GitHubService: Fetched Metadata for GitHub repository: {repo_owner}/{repo_name}")

        return MaintenanceStatus(
            package=f"{repo_owner}/{repo_name}",
            stars=stars,
            forks=forks,
            last_commit_date=last_commit_date,
            open_issues=open_issues,
            open_pull_requests=open_pull_requests
        )

    except GithubException as e:
        if e.status == 404:
            logger.warning(f"GitHub API error: Repository '{repo_owner}/{repo_name}' not found. Status: {e.status}")
        else:
            logger.error(f"GitHub API error: {e.status} - {e.data}", exc_info=True)
        return None

    except Exception as e:
        logger.error(f"GitHub API error: {e}", exc_info=True)
        return None
