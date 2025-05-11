# modules/bloodhound.py
import subprocess
import os
import json
from datetime import datetime
import time
import signal
import shutil

class BloodhoundModule:
    def __init__(self):
        self.output_dir = None
        self.raw_logs_dir = None
        self.parsed_dir = None
        self.dnschef_process = None
        
    def set_output_dir(self, output_dir, raw_logs_dir, parsed_dir):
        """Configure les répertoires de sortie"""
        self.output_dir = output_dir
        self.raw_logs_dir = raw_logs_dir
        self.parsed_dir = parsed_dir
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(raw_logs_dir, exist_ok=True)
        os.makedirs(parsed_dir, exist_ok=True)
        
    def collect_data(self, target_ip, domain, username, password):
        """
        Interface pour run_collection, assure la compatibilité avec le nouveau code
        """
        # Extraction du hostname depuis le domaine pour le DC
        # On suppose que le premier composant du domaine est le hostname du DC
        dc_hostname = domain.split('.')[0]
        
        return self.run_collection(
            target_ip=target_ip,
            domain=domain,
            username=username,
            password=password,
            dc_hostname=dc_hostname
        )
        
    def _setup_dns(self, target_ip, domain):
        """Configure DNSChef pour la résolution DNS"""
        print(f"[*] Configuration de DNSChef pour {domain}...")
        
        timestamp = datetime.now().strftime("%H%M%S")
        log_file = os.path.join(self.raw_logs_dir, f"dnschef_log_{timestamp}.txt")
        
        with open(log_file, 'w') as f:
            f.write(f"[*] Configuration DNSChef\n")
            f.write(f"[*] IP cible : {target_ip}\n")
            f.write(f"[*] Domaine : {domain}\n")
            f.write(f"[*] Démarrage à {datetime.now().strftime('%H:%M:%S')}\n\n")
            
            cmd = ["sudo", "dnschef", "--fakeip", target_ip, "--fakedomains", domain]
            
            try:
                self.dnschef_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    bufsize=1
                )
                
                # Attente que DNSChef soit prêt
                time.sleep(2)
                
                if self.dnschef_process.poll() is not None:
                    print("[!] Erreur lors du démarrage de DNSChef")
                    return False
                    
                print("[+] DNSChef démarré avec succès")
                return True
                
            except Exception as e:
                print(f"[!] Erreur lors du démarrage de DNSChef: {str(e)}")
                return False
                
    def _stop_dns(self):
        """Arrête le processus DNSChef"""
        if self.dnschef_process:
            self.dnschef_process.terminate()
            try:
                self.dnschef_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.dnschef_process.kill()
            self.dnschef_process = None
            
    def run_collection(self, target_ip, domain, username, password, dc_hostname):
        """Lance la collecte Bloodhound"""
        print(f"\n[*] Démarrage de la collecte Bloodhound pour {domain}")
        
        # Configuration de DNSChef
        if not self._setup_dns(target_ip, domain):
            return None
            
        try:
            timestamp = datetime.now().strftime("%H%M%S")
            log_file = os.path.join(self.raw_logs_dir, f"bloodhound_log_{timestamp}.txt")
            
            # Construction de la commande Bloodhound
            cmd = [
                "bloodhound-python",
                "-u", username,
                "-p", password,
                "-d", domain,
                "--zip",
                "-c", "all,loggedon",
                "-dc", f"{dc_hostname}.{domain}",
                "-ns", "127.0.0.1",
                "--disable-pooling"
            ]
            
            # Exécution de Bloodhound
            with open(log_file, 'w') as f:
                f.write(f"[*] Commande : {' '.join(cmd)}\n")
                f.write(f"[*] Démarrage à {datetime.now().strftime('%H:%M:%S')}\n\n")
                
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    bufsize=1
                )
                
                zip_file = None
                
                # Lecture des sorties en temps réel
                while True:
                    line = process.stdout.readline()
                    if not line and process.poll() is not None:
                        break
                        
                    if line:
                        line = line.strip()
                        print(line)
                        f.write(f"{line}\n")
                        f.flush()
                        
                        # Détection du fichier ZIP généré
                        if ".zip" in line:
                            zip_file = line.strip()
                
                # Lecture des erreurs
                for line in process.stderr:
                    line = line.strip()
                    print(f"[!] {line}")
                    f.write(f"[!] {line}\n")
                    f.flush()
                    
            # Déplacement de tous les fichiers .zip dans le dossier de résultats
            current_dir = os.getcwd()
            zip_files = [f for f in os.listdir(current_dir) if f.endswith('.zip')]
            
            for zip_file in zip_files:
                src_path = os.path.join(current_dir, zip_file)
                dst_path = os.path.join(self.output_dir, zip_file)
                
                # Si le fichier existe déjà dans la destination, on le supprime
                if os.path.exists(dst_path):
                    os.remove(dst_path)
                    
                # Déplacement du fichier
                shutil.move(src_path, dst_path)
                zip_file = dst_path
            
            # Sauvegarde des métadonnées
            results = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "target": target_ip,
                "domain": domain,
                "dc_hostname": dc_hostname,
                "username": username,
                "log_file": log_file,
                "zip_file": zip_file if zip_file else None
            }
            
            results_file = os.path.join(self.parsed_dir, f"bloodhound_meta_{timestamp}.json")
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=4)
                
            print(f"[+] Log complet sauvegardé dans {log_file}")
            print(f"[+] Métadonnées sauvegardées dans {results_file}")
            if zip_file:
                print(f"[+] Données Bloodhound sauvegardées dans {zip_file}")
                
            return results
            
        finally:
            # Arrêt de DNSChef
            self._stop_dns()
            
    def __del__(self):
        """Destructeur pour s'assurer que DNSChef est arrêté"""
        self._stop_dns()
