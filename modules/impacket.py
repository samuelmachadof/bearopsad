# modules/impacket.py
from utils import run_cmd

def smb_exec(target, user, pwd):
    cmd = ["impacket-smbexec", "-target", target, "-user", user, "-pass", pwd]
    out = run_cmd(cmd)
    return out
