from utils import run_cmd
import os
import sys
import json
from pathlib import Path
import time

class CertipyModule:
    def __init__(self):
        self.output_dir = None
        self.raw_logs_dir = None
        self.parsed_dir = None
        
    def set_output_dir(self, output_dir, raw_logs_dir, parsed_dir):
        self.output_dir = output_dir
        self.raw_logs_dir = raw_logs_dir
        self.parsed_dir = parsed_dir
        
    def test_shadow_credentials(self, target, domain, username, password, dc_hostname):
        """
        Teste la vulnérabilité aux Shadow Credentials (DACL misconfiguration) 
        en utilisant Certipy
        
        Returns:
            dict: Résultats du test
        """
        print(f"[*] Test de Shadow Credentials attack contre {domain}")
        
        output_file = os.path.join(self.raw_logs_dir, f"certipy_shadow_creds_{int(time.time())}.txt")
        
        # Commande pour find (trouver les utilisateurs/machines avec des droits msDS-KeyCredentialLink)
        cmd_find = [
            "certipy", "find", 
            "-u", f"{username}@{domain}", 
            "-p", password,
            "-dc-ip", target,
            "-vulnerable", "Shadow",
            "-output", os.path.join(self.raw_logs_dir, f"certipy_find_{domain}")
        ]
        
        find_output = run_cmd(cmd_find, real_time=True, save_output=True)
        find_success = find_output is not None
        
        # Analyse des résultats pour trouver les cibles vulnérables
        vulnerable_targets = []
        
        if find_success:
            # Analyse du fichier JSON de sortie
            results_file = os.path.join(self.raw_logs_dir, f"certipy_find_{domain}.json")
            if os.path.exists(results_file):
                try:
                    with open(results_file, 'r') as f:
                        find_results = json.load(f)
                        
                    # Extraction des cibles vulnérables
                    for obj_name, obj_data in find_results.get("objects", {}).items():
                        if obj_data.get("shadowCredentials", False):
                            vulnerable_targets.append({
                                "name": obj_name,
                                "distinguishedName": obj_data.get("distinguishedName"),
                                "objectSid": obj_data.get("objectSid")
                            })
                except Exception as e:
                    print(f"[!] Erreur lors de l'analyse des résultats: {str(e)}")
        
        # Test d'exploitation si des cibles vulnérables sont trouvées
        exploitation_results = []
        
        if vulnerable_targets:
            print(f"[+] {len(vulnerable_targets)} cibles potentiellement vulnérables trouvées")
            
            # Pour chaque cible, on tente d'exploiter (optionnel, dangereux en environnement de production)
            # Le test complet peut être désactivé ou effectué manuellement
            for target_info in vulnerable_targets[:1]:  # Limiter à la première cible pour les tests
                exploitation_results.append({
                    "target": target_info["name"],
                    "vulnerable": True,
                    "exploited": False,  # Par défaut, nous ne testons pas l'exploitation complète
                    "details": "DACL permet la modification de msDS-KeyCredentialLink"
                })
        
        # Résultats finaux
        results = {
            "timestamp": int(time.time()),
            "domain": domain,
            "dc": dc_hostname,
            "vulnerable_targets": vulnerable_targets,
            "exploitation_results": exploitation_results,
            "raw_output_file": output_file
        }
        
        # Sauvegarde des résultats parsés
        parsed_file = os.path.join(self.parsed_dir, f"certipy_shadow_creds_{int(time.time())}.json")
        with open(parsed_file, 'w') as f:
            json.dump(results, f, indent=4)
            
        return results

def find_vulnerable_templates(target, username=None, password=None):
    """Recherche des templates de certificats vulnérables"""
    cmd = ["certipy", "find", "-target", target]
    if username and password:
        cmd.extend(["-u", username, "-p", password])
    return run_cmd(cmd)

def request_cert(target, username, password, template):
    """Demande un certificat en utilisant un template spécifique"""
    cmd = ["certipy", "req", "-target", target, 
           "-u", username, "-p", password,
           "-template", template]
    return run_cmd(cmd)

def relay_cert(target, listener_port=445):
    """Configure un relais de certificat"""
    cmd = ["certipy", "relay", "-target", target,
           "-port", str(listener_port)]
    return run_cmd(cmd)

def auth_cert(target, cert_path, key_path):
    """Authentification avec un certificat"""
    cmd = ["certipy", "auth", "-target", target,
           "-cert", cert_path, "-key", key_path]
    return run_cmd(cmd) 