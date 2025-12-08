import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()
api_key = os.getenv("OPENAI_API_KEY")
if not api_key: raise ValueError("No API Key found!")

client = OpenAI(api_key=api_key)

def analyze_log(log_line):
    system_prompt = "You are a cyber security expert. Analyze server logs."
    
    user_prompt = f"""
    Analyze this log entry: '{log_line}'
    
    If it is SAFE, respond with just the word: SAFE.
    
    If it is MALICIOUS, respond in this exact format:
    RISK: [High/Medium/Low]
    TYPE: [Attack Name]
    MITIGATION: [One short sentence on how to fix it]
    """

    try:
        response = client.chat.completions.create(
            model="gpt-4o", 
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Error: {e}"

if __name__ == "__main__":
    print("🕵️  AI Agent scanning large dataset...")
    
    with open("server.log", "r") as f:
        logs = f.readlines()

    report_file = "security_summary.txt"
    with open(report_file, "w") as f:
        f.write("🔒 SECURITY INCIDENT REPORT\n")
        f.write("==============================================\n\n\n")

    malicious_count = 0

    for line in logs:
        line = line.strip()
        if not line: continue
        
        print(".", end="", flush=True)
        
        analysis = analyze_log(line)
        
        if "SAFE" not in analysis:
            malicious_count += 1
            print(f"\n[!] ALERT FOUND: {line[:30]}...") 
            
            with open(report_file, "a") as f:
                f.write(f"LOG: {line}\n")
                f.write(f"{analysis}\n")
                f.write("-" * 40 + "\n")

    print(f"\n\n✅ Scan Complete.")
    print(f"📊 Found {malicious_count} malicious entries.")
    print(f"📄 Report saved to: {report_file}")