"""Discover high-quality blockchain/crypto repos on GitHub."""
import json
import os
import sys
import time
import argparse
import requests
from datetime import datetime

GITHUB_API = "https://api.github.com"

def search_repos(token, languages, topics, min_stars, max_results=100):
    """Search GitHub for blockchain repos."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    all_repos = []
    seen = set()
    
    # Search by language
    for lang in languages.split(","):
        lang = lang.strip()
        query = f"language:{lang} stars:>={min_stars}"
        if topics:
            topic_query = " OR ".join(f"topic:{t.strip()}" for t in topics.split(",")[:5])
            query += f" ({topic_query})"
        
        page = 1
        while len(all_repos) < max_results:
            params = {
                "q": query,
                "sort": "stars",
                "order": "desc",
                "per_page": min(30, max_results - len(all_repos)),
                "page": page
            }
            
            try:
                resp = requests.get(f"{GITHUB_API}/search/repositories", 
                                   headers=headers, params=params, timeout=30)
                if resp.status_code == 403:
                    print(f"Rate limited, waiting...")
                    time.sleep(60)
                    continue
                resp.raise_for_status()
                data = resp.json()
                items = data.get("items", [])
                
                if not items:
                    break
                
                for repo in items:
                    rid = repo["full_name"]
                    if rid not in seen:
                        seen.add(rid)
                        all_repos.append({
                            "full_name": rid,
                            "url": repo["html_url"],
                            "clone_url": repo["clone_url"],
                            "stars": repo["stargazers_count"],
                            "language": repo["language"],
                            "topics": repo.get("topics", []),
                            "description": repo.get("description", ""),
                            "default_branch": repo["default_branch"],
                            "discovered_at": datetime.utcnow().isoformat() + "Z"
                        })
                
                page += 1
                time.sleep(2)  # Rate limit courtesy
                
            except requests.exceptions.RequestException as e:
                print(f"Search error: {e}", file=sys.stderr)
                break
    
    return all_repos[:max_results]

def search_by_topic(token, topics, min_stars, max_results=100):
    """Additional search by topics."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    all_repos = []
    seen = set()
    
    for topic in topics.split(",")[:5]:
        topic = topic.strip()
        query = f"topic:{topic} stars:>={min_stars}"
        
        params = {
            "q": query,
            "sort": "stars",
            "order": "desc",
            "per_page": 20
        }
        
        try:
            resp = requests.get(f"{GITHUB_API}/search/repositories",
                               headers=headers, params=params, timeout=30)
            if resp.status_code != 200:
                continue
            data = resp.json()
            
            for repo in data.get("items", []):
                rid = repo["full_name"]
                if rid not in seen:
                    seen.add(rid)
                    all_repos.append({
                        "full_name": rid,
                        "url": repo["html_url"],
                        "clone_url": repo["clone_url"],
                        "stars": repo["stargazers_count"],
                        "language": repo["language"],
                        "topics": repo.get("topics", []),
                        "description": repo.get("description", ""),
                        "default_branch": repo["default_branch"],
                        "discovered_at": datetime.utcnow().isoformat() + "Z"
                    })
            
            time.sleep(2)
        except Exception as e:
            print(f"Topic search error for {topic}: {e}", file=sys.stderr)
    
    return all_repos

def main():
    parser = argparse.ArgumentParser(description="Discover blockchain repos")
    parser.add_argument("--min-stars", type=int, default=50)
    parser.add_argument("--languages", default="Solidity,Rust,Go,TypeScript,Move")
    parser.add_argument("--topics", default="blockchain,cryptocurrency,smart-contracts,defi,web3")
    parser.add_argument("--max-repos", type=int, default=100)
    parser.add_argument("--output", default="discovered_repos.jsonl")
    parser.add_argument("--state", default="discover_state.json")
    args = parser.parse_args()
    
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("ERROR: GITHUB_TOKEN not set", file=sys.stderr)
        sys.exit(1)
    
    # Load previous state
    seen_repos = set()
    if os.path.exists(args.state):
        with open(args.state, "r") as f:
            state = json.load(f)
            seen_repos = set(state.get("seen_repos", []))
    
    # Search
    print(f"Searching GitHub for blockchain repos (stars >= {args.min_stars})...")
    repos = search_repos(token, args.languages, args.topics, args.min_stars, args.max_repos)
    topic_repos = search_by_topic(token, args.topics, args.min_stars, args.max_repos // 2)
    
    # Merge and deduplicate
    all_repos = {}
    for r in repos + topic_repos:
        all_repos[r["full_name"]] = r
    
    # Filter new
    new_repos = []
    for name, repo in all_repos.items():
        if name not in seen_repos:
            new_repos.append(repo)
            seen_repos.add(name)
    
    # Write output
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "a", encoding="utf-8") as f:
        for repo in new_repos:
            f.write(json.dumps(repo, ensure_ascii=False) + "\n")
    
    # Update state
    with open(args.state, "w") as f:
        json.dump({"seen_repos": list(seen_repos), "last_run": datetime.utcnow().isoformat() + "Z"}, f)
    
    print(f"Found {len(new_repos)} new repos (total tracked: {len(seen_repos)})")
    
    # Set output for GitHub Actions
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"new_repos={len(new_repos)}\n")

if __name__ == "__main__":
    main()
