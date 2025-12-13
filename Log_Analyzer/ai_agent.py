import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()
api_key = os.getenv("OPENAI_API_KEY")
if not api_key: raise ValueError("No API Key found!")

client = OpenAI(api_key=api_key)

BATCH_SIZE = 5 

def analyze_log_batch(log_lines):
    
    batch_text = ""
    for i, line in enumerate(log_lines):
        batch_text += f"Line {i+1}: {line}\n"

    system_prompt = """
    You are a Tier 2 SOC Analyst. 
    Analyze the provided sequence of server logs looking for patterns.
    Look for: Brute Force (repeated failures), Port Scans, or Multi-stage attacks.
    """
    
    user_prompt = f""" 
    Analyze this log batch:\n{batch_text}
    
    Instructions:
    1. If ALL lines are normal/safe, respond with exactly: SAFE.
    2. If you detect a suspicious PATTERN or specific malicious lines, respond in this format:
    
    PATTERN DETECTED: [Name of attack, e.g., Brute Force / SQL Injection]
    SEVERITY: [High/Medium/Low]
    AFFECTED LINES: [Which line numbers are involved]
    EXPLANATION: [Brief explanation of why this sequence is suspicious]
    MITIGATION: [Action to take]
    """

    try:
        response = client.chat.completions.create(
            model="gpt-4o", 
            temperature=0,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Error: {e}"

if __name__ == "__main__":
    print(f"  AI Agent scanning with Batch Logic (Batch Size: {BATCH_SIZE})...")
    
    with open("server.log", "r") as f:
        logs = f.readlines()

    report_file = "security_summary_batch.txt"
    with open(report_file, "w") as f:
        f.write(" SECURITY INCIDENT REPORT (CONTEXT AWARE)\n")
        f.write("==============================================\n\n")

    malicious_batches = 0
    current_batch = []

    for i, line in enumerate(logs):
        line = line.strip()
        if not line: continue
        
        current_batch.append(line)
        
        if len(current_batch) >= BATCH_SIZE:
            print(".", end="", flush=True)
            
            analysis = analyze_log_batch(current_batch)
            
            if "SAFE" not in analysis:
                malicious_batches += 1
                print(f"\n[!] THREAT PATTERN DETECTED in batch ending at line {i+1}!")
                
                with open(report_file, "a") as f:
                    f.write(f"--- BATCH ANALYSIS (Lines {i+1-BATCH_SIZE} to {i+1}) ---\n")
                    f.write(f"LOGS:\n")
                    for batch_line in current_batch:
                        f.write(f"> {batch_line}\n")
                    f.write(f"\nAI FINDINGS:\n{analysis}\n")
                    f.write("\n" + "="*50 + "\n\n")
            
            current_batch = []

    if current_batch:
        print(".", end="", flush=True)
        analysis = analyze_log_batch(current_batch)
        if "SAFE" not in analysis:
            malicious_batches += 1
            with open(report_file, "a") as f:
                f.write(f"--- FINAL BATCH ANALYSIS ---\n")
                f.write(f"{analysis}\n")

    print(f"\n\n Scan Complete.")
    print(f" Found {malicious_batches} suspicious batches.")
    print(f" Report saved to: {report_file}")