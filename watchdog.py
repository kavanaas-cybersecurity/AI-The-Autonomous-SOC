import requests
import urllib3
import json
import ollama
import time
import os
from datetime import datetime, timedelta
from jira import JIRA
from dotenv import load_dotenv

# Load credentials from .env file
load_dotenv()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration from Environment Variables
INDEXER_URL = os.getenv("INDEXER_URL")
AUTH = (os.getenv("WAZUH_USER"), os.getenv("WAZUH_PASS"))
JIRA_SERVER = os.getenv("JIRA_SERVER")
JIRA_EMAIL = os.getenv("JIRA_EMAIL")
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN")
PROJECT_KEY = os.getenv("JIRA_PROJECT_KEY")

def create_jira_ticket(title, level, log_detail, ai_analysis):
    try:
        jira = JIRA(server=JIRA_SERVER, basic_auth=(JIRA_EMAIL, JIRA_API_TOKEN))
        issue_dict = {
            'project': {'key': PROJECT_KEY},
            'summary': f"[Level {level}] AUTONOMOUS SOC ALERT: {title}",
            'description': f"Raw Log Detail: {log_detail}\n\nAI Analysis:\n{ai_analysis}",
            'issuetype': {'name': 'Task'}, 
        }
        new_issue = jira.create_issue(fields=issue_dict)
        print(f"✅ Ticket Created! -> {JIRA_SERVER}/browse/{new_issue.key}")
    except Exception as e:
        print(f"❌ JIRA Error: {e}")

def run_autonomous_soc():
    print("--- 🤖 AI: THE AUTONOMOUS SOC ACTIVE ---")
    
    # Bridge the UTC timezone gap
    last_seen_time = (datetime.utcnow() - timedelta(hours=12)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    print(f"Listening for new threats since: {last_seen_time} (UTC)\n")

    while True:
        search_url = f"{INDEXER_URL}/wazuh-alerts-*/_search"
        
        query = {
            "size": 10,
            "sort": [{"@timestamp": {"order": "asc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"match": {"rule.groups": "sca"}},
                        {"match": {"data.sca.check.result": "failed"}},
                        {"range": {"rule.level": {"gte": 7, "lte": 11}}},
                        {"range": {"@timestamp": {"gt": last_seen_time}}} 
                    ]
                }
            },
            "_source": ["@timestamp", "rule.level", "data.sca.check.title", "data.sca.check.remediation"]
        }

        try:
            res = requests.get(search_url, auth=AUTH, json=query, verify=False)
            if res.status_code == 200:
                hits = res.json().get('hits', {}).get('hits', [])
                if hits:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🚨 {len(hits)} NEW ALERT(S) DETECTED!")
                    for hit in hits:
                        source = hit.get('_source', {})
                        last_seen_time = source.get('@timestamp')
                        
                        title = source.get('data', {}).get('sca', {}).get('check', {}).get('title', 'Unknown')
                        remediation = source.get('data', {}).get('sca', {}).get('check', {}).get('remediation', 'N/A')
                        level = source.get('rule', {}).get('level', 'Unknown')
                        
                        print(f">> Analyzing Level {level}: {title}")
                        
                        # 1. Define the rules in the System role
                        system_prompt = (
                            "You are a strict, highly skilled SOC Analyst. "
                            "Your job is to review security alerts. "
                            "Rules: Explain the risk in exactly one sentence. Suggest a fix based strictly on standard frameworks (like CIS or NIST). NEVER make up or hallucinate commands."
                        )
                        
                        # 2. Pass the specific alert data in the User role
                        user_prompt = f"Alert Title: '{title}'\nSuggested Remediation: '{remediation}'"
                        
                        # 3. Send both to Ollama
                        ai_res = ollama.chat(model='llama3', messages=[
                            {'role': 'system', 'content': system_prompt},
                            {'role': 'user', 'content': user_prompt}
                        ])
                        ai_analysis = ai_res['message']['content']
                        
                        print(f"🤖 AI Response: {ai_analysis[:100]}...")
                        create_jira_ticket(title, level, remediation, ai_analysis)
            
            time.sleep(10)
        except Exception as e:
            print(f"Connection Error: {e}")
            time.sleep(10)

if __name__ == "__main__":
    run_autonomous_soc()
