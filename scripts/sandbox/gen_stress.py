import os
import random
import uuid

BASE_DIR = "f:/Adversum/adversum/stress_test_project"
FILE_COUNT = 5000
VULN_RATIO = 0.01 # 1% vulnerable files = 50 vulnerabilities

def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)

def generate_safe_code():
    return f"""
def safe_function_{uuid.uuid4().hex[:8]}():
    data = "{uuid.uuid4().hex}"
    print(f"Processing {{data}}")
    return len(data) * {random.randint(1, 100)}
"""

def generate_vuln_code():
    vuln_type = random.choice(['secret', 'cmd', 'sql', 'path'])
    if vuln_type == 'secret':
        return f"""
def connect_db():
    # Hardcoded secret
    AWS_ACCESS_KEY = "AKIA{uuid.uuid4().hex[:16].upper()}" 
    pass
"""
    elif vuln_type == 'cmd':
        return f"""
import subprocess
def run_cmd(user_input):
    subprocess.run(f"echo {{user_input}}", shell=True)
"""
    elif vuln_type == 'sql':
        return f"""
def query_db(uid):
    q = "SELECT * FROM users WHERE id = " + uid
    execute(q)
"""
    else:
        return f"""
def read_file(path):
    open(f"/var/www/{{path}}", "r")
"""

def main():
    print(f"Generating {FILE_COUNT} files in {BASE_DIR}...")
    ensure_dir(BASE_DIR)
    
    # Clean previous
    import shutil
    if os.path.exists(BASE_DIR):
        shutil.rmtree(BASE_DIR)
    ensure_dir(BASE_DIR)

    for i in range(FILE_COUNT):
        is_vuln = random.random() < VULN_RATIO
        content = generate_vuln_code() if is_vuln else generate_safe_code()
        
        # Deep nesting folder structure simulation
        folder = os.path.join(BASE_DIR, f"module_{i % 50}", f"sub_{i % 10}")
        ensure_dir(folder)
        
        fname = f"file_{i}.py"
        with open(os.path.join(folder, fname), "w") as f:
            f.write(content)
            
    print("Done! Ready for STRESS TEST.")

if __name__ == "__main__":
    main()
