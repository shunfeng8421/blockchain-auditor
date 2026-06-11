"""Polish case study using AI (OpenAI API)."""
import os
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--draft", default="auditor/case-studies/draft.md")
    parser.add_argument("--output", default="auditor/case-studies/final.md")
    args = parser.parse_args()
    
    api_key = os.environ.get("OPENAI_API_KEY")
    
    with open(args.draft, "r", encoding="utf-8") as f:
        draft = f.read()
    
    if api_key:
        try:
            import requests
            resp = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "gpt-4o-mini",
                    "messages": [
                        {"role": "system", "content": "You are a blockchain security expert. Polish the following case study. Add a compelling title, improve clarity, and ensure technical accuracy. Keep the same structure."},
                        {"role": "user", "content": draft}
                    ],
                    "max_tokens": 4000
                },
                timeout=60
            )
            resp.raise_for_status()
            polished = resp.json()["choices"][0]["message"]["content"]
        except Exception as e:
            print(f"AI polish failed: {e}. Using draft as-is.")
            polished = draft
    else:
        print("No OPENAI_API_KEY set. Using draft as-is.")
        polished = draft
    
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(polished)
    
    print(f"Final case study written to {args.output}")

if __name__ == "__main__":
    main()
