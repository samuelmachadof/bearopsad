# modules/kerbrute.py
from utils import run_cmd
import os
import shutil
from datetime import datetime
import json
import subprocess

class KerbruteModule:
    def __init__(self):
        self.output_dir = None
        self.raw_logs_dir = None
        self.parsed_dir = None
        
    def set_output_dir(self, output_dir, raw_logs_dir, parsed_dir):
        """Configure les répertoires de sortie"""
        self.output_dir = output_dir
        self.raw_logs_dir = raw_logs_dir
        self.parsed_dir = parsed_dir
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(raw_logs_dir, exist_ok=True)
        os.makedirs(parsed_dir, exist_ok=True)

    def find_kerbrute(self):
        """Trouve l'exécutable kerbrute"""
        possible_paths = [
            "./kerbrute",
            "~/go/bin/kerbrute",
            "/usr/local/bin/kerbrute",
            "/usr/bin/kerbrute",
            "../tools/kerbrute",
            "/home/samy/kerbrute_linux_amd64"
        ]
        
        # Expansion du ~
        possible_paths = [os.path.expanduser(p) for p in possible_paths]
        
        # Test des chemins possibles
        for path in possible_paths:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
                
        # Vérification dans le PATH
        kerbrute_path = shutil.which("kerbrute")
        if kerbrute_path:
            return kerbrute_path
            
        raise FileNotFoundError(
            "Kerbrute non trouvé. Installez-le avec:\n"
            "go install github.com/ropnop/kerbrute@latest"
        )

    def enum_users(self, target, wordlist, domain):
        """Énumération des utilisateurs avec Kerbrute"""
        print(f"[*] Énumération des utilisateurs sur {domain}...")
        
        # Vérification de l'existence de la wordlist
        if not os.path.exists(wordlist):
            print(f"[!] Wordlist non trouvée: {wordlist}")
            return {
                "error": "Wordlist non trouvée",
                "wordlist": wordlist
            }
            
        # Création du fichier de log
        timestamp = datetime.now().strftime("%H%M%S")
        log_file = os.path.join(self.raw_logs_dir, f"kerbrute_log_{timestamp}.txt")
        users_file = os.path.join(self.parsed_dir, "users_kerbrute.txt")
        
        # Recherche de l'exécutable kerbrute
        try:
            kerbrute_path = self.find_kerbrute()
        except FileNotFoundError as e:
            error_msg = str(e)
            print(f"[!] {error_msg}")
            
            # Création des fichiers même en cas d'erreur
            with open(log_file, 'w') as log:
                log.write(f"[!] {error_msg}\n")
            with open(users_file, 'w') as users:
                users.write("# Aucun utilisateur trouvé - Kerbrute non disponible\n")
                
            return {
                "error": error_msg,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "target": target,
                "domain": domain,
                "wordlist": wordlist,
                "valid_users": [],
                "total_users": 0,
                "log_file": log_file,
                "users_file": users_file
            }
            
        # Construction de la commande
        cmd = [
            kerbrute_path,
            "userenum",
            "--dc", target,
            "-d", domain,
            wordlist
        ]
        
        # Ouverture des fichiers de sortie
        with open(log_file, 'w') as log, open(users_file, 'w') as users:
            log.write(f"[*] Commande : {' '.join(cmd)}\n")
            log.write(f"[*] Démarrage à {datetime.now().strftime('%H:%M:%S')}\n\n")
            
            # Lancement du processus
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )
            
            valid_users = set()
            
            # Lecture des sorties en temps réel
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                    
                if line:
                    line = line.strip()
                    print(line)
                    log.write(f"{line}\n")
                    log.flush()
                    
                    # Extraction des utilisateurs valides
                    if "VALID USERNAME:" in line:
                        user = line.split("VALID USERNAME:")[1].strip()
                        valid_users.add(user)
                        users.write(f"{user}\n")
                        users.flush()
            
            # Lecture des erreurs
            for line in process.stderr:
                line = line.strip()
                print(f"[!] {line}")
                log.write(f"[!] {line}\n")
                log.flush()
                
        # Sauvegarde des résultats
        results = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": target,
            "domain": domain,
            "wordlist": wordlist,
            "valid_users": list(valid_users),
            "total_users": len(valid_users),
            "log_file": log_file,
            "users_file": users_file
        }
        
        results_file = os.path.join(self.parsed_dir, f"kerbrute_results_{timestamp}.json")
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=4)
            
        print(f"\n[+] {len(valid_users)} utilisateurs valides trouvés")
        print(f"[+] Log complet sauvegardé dans {log_file}")
        print(f"[+] Utilisateurs valides sauvegardés dans {users_file}")
        print(f"[+] Résultats détaillés sauvegardés dans {results_file}")
        
        return results

    def get_results(self):
        """Retourne les résultats de l'énumération"""
        return {
            "valid_users": self.valid_users,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "total_users": len(self.valid_users)
        }
