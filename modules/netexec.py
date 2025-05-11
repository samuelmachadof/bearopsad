# modules/netexec.py
from utils import run_cmd
import json
import re
from datetime import datetime
import shutil
import os
import subprocess

class NetexecModule:
    def __init__(self):
        self.supported_protocols = ["smb", "ssh", "ldap", "winrm", "rdp", "mssql", "nfs", "ftp"]
        self.results = {}
        self.vulnerabilities = []
        self.valid_users = set()
        self.valid_credentials = []
        self.shares = []
        self.domain_info = None
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
        os.makedirs(os.path.join(output_dir, "spider_plus"), exist_ok=True)

    def detect_domain(self, target):
        """Détection initiale du domaine"""
        print(f"[*] Détection du domaine pour {target}...")
        
        # Création du fichier de log
        timestamp = datetime.now().strftime("%H%M%S")
        log_file = os.path.join(self.raw_logs_dir, f"domain_detection_log_{timestamp}.txt")
        
        # Lancement de la commande avec logging
        cmd = ["nxc", "smb", target]
        
        # Ouverture du fichier de log
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
            
            output_lines = []
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                    
                if line:
                    line = line.strip()
                    print(line)
                    f.write(f"{line}\n")
                    f.flush()
                    output_lines.append(line)
            
            for line in process.stderr:
                line = line.strip()
                print(f"[!] {line}")
                f.write(f"[!] {line}\n")
                f.flush()
                
        # Parse la sortie pour extraire les informations
        domain_info = {
            "domain": None,
            "hostname": None,
            "os": None
        }
        
        for line in output_lines:
            if "[*]" in line and "SMB" in line:
                domain_match = re.search(r"domain:(.*?)\)", line)
                if domain_match:
                    domain_info["domain"] = domain_match.group(1).strip()
                
                name_match = re.search(r"\(name:(.*?)\)", line)
                if name_match:
                    domain_info["hostname"] = name_match.group(1).strip()
                
                os_match = re.search(r"Windows.*?(x64|x86)", line)
                if os_match:
                    domain_info["os"] = os_match.group(0)
        
        self.domain_info = domain_info
        
        # Sauvegarde des résultats parsés
        results_file = os.path.join(self.parsed_dir, f"domain_detection_{timestamp}.json")
        with open(results_file, 'w') as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "target": target,
                "domain_info": domain_info,
                "log_file": log_file
            }, f, indent=4)
            
        print(f"[+] Log complet sauvegardé dans {log_file}")
        print(f"[+] Résultats sauvegardés dans {results_file}")
        
        return domain_info

    def _parse_spider_results(self, spider_results):
        """Parse les résultats du spider_plus pour extraire les informations importantes"""
        if not spider_results or not isinstance(spider_results, dict):
            return None
            
        parsed = {}
        for share_name, share_data in spider_results.items():
            if share_name.lower() not in ["c$", "admin$", "ipc$"]:
                parsed[share_name] = {
                    "files": [],
                    "folders": [],
                    "writable": share_data.get("writable", False)
                }
                
                # Analyse des fichiers
                for file_info in share_data.get("files", []):
                    if isinstance(file_info, dict):
                        file_path = file_info.get("path", "")
                        parsed[share_name]["files"].append(file_path)
                        
                # Analyse des dossiers
                for folder_info in share_data.get("folders", []):
                    if isinstance(folder_info, dict):
                        folder_path = folder_info.get("path", "")
                        parsed[share_name]["folders"].append(folder_path)
                        
        return parsed

    def spider_plus(self, target, username, password):
        """Lance le module spider_plus pour énumérer les partages"""
        print(f"[*] Lancement de spider_plus avec {username}...")
        
        # Création des dossiers
        spider_dir = os.path.join(self.output_dir, "spider_plus")
        os.makedirs(spider_dir, exist_ok=True)
        
        # Création du fichier de log
        timestamp = datetime.now().strftime("%H%M%S")
        log_file = os.path.join(self.raw_logs_dir, f"spider_plus_log_{timestamp}.txt")
        
        cmd = ["nxc", "smb", target, "-u", username, "-p", password, "-M", "spider_plus"]
        
        with open(log_file, 'w') as f:
            f.write(f"[*] Commande : {' '.join(cmd)}\n")
            f.write(f"[*] Démarrage à {datetime.now().strftime('%H:%M:%S')}\n")
            f.write(f"[*] Utilisateur : {username}\n\n")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )
            
            output_lines = []
            json_path = None
            
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                    
                if line:
                    line = line.strip()
                    print(line)
                    f.write(f"{line}\n")
                    f.flush()
                    output_lines.append(line)
                    
                    if 'Saved share-file metadata to "' in line:
                        json_path = line.split('"')[1]
            
            for line in process.stderr:
                line = line.strip()
                print(f"[!] {line}")
                f.write(f"[!] {line}\n")
                f.flush()
                
        # Copie et traitement du JSON si trouvé
        if json_path and os.path.exists(json_path):
            dest_json = os.path.join(spider_dir, f"{target}_spider_plus.json")
            shutil.copy2(json_path, dest_json)
            print(f"[+] Résultats spider_plus sauvegardés dans {dest_json}")
            
            # Lecture et parsing du JSON
            with open(dest_json) as f:
                spider_results = json.load(f)
                
            # Parse des résultats
            parsed_results = self._parse_spider_results(spider_results)
                
            # Sauvegarde des métadonnées
            metadata_file = os.path.join(self.parsed_dir, f"spider_plus_meta_{timestamp}.json")
            with open(metadata_file, 'w') as f:
                json.dump({
                    "timestamp": datetime.now().isoformat(),
                    "target": target,
                    "username": username,
                    "log_file": log_file,
                    "json_file": dest_json,
                    "stats": {
                        "total_files": len([f for s in parsed_results.values() for f in s["files"]]),
                        "total_dirs": len([d for s in parsed_results.values() for d in s["folders"]]),
                        "shares": list(parsed_results.keys())
                    } if parsed_results else {}
                }, f, indent=4)
                
            return {
                "output": "\n".join(output_lines),
                "json_path": dest_json,
                "log_file": log_file,
                "metadata_file": metadata_file,
                "results": parsed_results
            }
        
        return {"output": "\n".join(output_lines), "json_path": None, "results": None, "log_file": log_file}

    def _parse_smb_output(self, output):
        """Parse la sortie SMB pour extraire les informations importantes"""
        results = {
            "signing": None,
            "guest_allowed": False,
            "null_session": False,
            "shares": [],
            "os_info": None,
            "domain": None,
            "naming_context": None
        }
        
        if not output:
            return results

        for line in output.split('\n'):
            if "[*]" in line and "SMB" in line:
                # Extraction des infos OS
                os_match = re.search(r"Windows.*?(x64|x86)", line)
                if os_match:
                    results["os_info"] = os_match.group(0)
                # Extraction du domaine
                domain_match = re.search(r"\(domain:(.*?)\)", line)
                if domain_match:
                    results["domain"] = domain_match.group(1).strip()
                # Vérification signing
                if "signing:True" in line:
                    results["signing"] = True
                elif "signing:False" in line:
                    results["signing"] = False
                    self.vulnerabilities.append("SMB Signing désactivé - Potentiel pour du NTLM Relay")

            elif "[+]" in line:
                # Détection connexion anonyme/guest
                if "Guest session" in line or "NULL session" in line:
                    results["guest_allowed"] = True
                    results["null_session"] = "NULL session" in line
                    self.vulnerabilities.append("Connexion anonyme autorisée")

            elif "SHARE" in line:
                # Extraction des partages
                share_match = re.search(r"\\\\.*\\(.*?)\s+.*?\s+(.*?)$", line)
                if share_match:
                    share_name, share_type = share_match.groups()
                    results["shares"].append({
                        "name": share_name.strip(),
                        "type": share_type.strip(),
                        "readable": "READ" in line,
                        "writable": "WRITE" in line
                    })

        return results

    def _parse_ldap_output(self, output):
        """Parse la sortie LDAP pour extraire les informations importantes"""
        results = {
            "naming_contexts": [],
            "users": [],
            "groups": [],
            "computers": [],
            "policies": []
        }
        
        if not output:
            return results

        for line in output.split('\n'):
            if "namingContexts:" in line:
                context = line.split("namingContexts:", 1)[1].strip()
                results["naming_contexts"].append(context)
            
            elif "[*] User:" in line:
                user = line.split("[*] User:", 1)[1].strip()
                results["users"].append(user)
                self.valid_users.add(user)
                
            elif "[*] Group:" in line:
                group = line.split("[*] Group:", 1)[1].strip()
                results["groups"].append(group)
                
            elif "[*] Computer:" in line:
                computer = line.split("[*] Computer:", 1)[1].strip()
                results["computers"].append(computer)

        return results

    def scan(self, target, protocol="smb", username=None, password=None, options=None):
        """Scan avancé avec NetExec"""
        if protocol not in self.supported_protocols:
            raise ValueError(f"Protocole non supporté: {protocol}")

        cmd = ["netexec", protocol, target]
        
        # Gestion des credentials
        if username:
            if isinstance(username, list):
                cmd.extend(["-u", ",".join(username)])
            else:
                cmd.extend(["-u", username])
        
        if password:
            if isinstance(password, list):
                cmd.extend(["-p", ",".join(password)])
            else:
                cmd.extend(["-p", password])

        # Options spécifiques par protocole
        if options:
            if protocol == "smb":
                if options.get("shares"):
                    cmd.append("--shares")
                if options.get("sessions"):
                    cmd.append("--sessions")
                if options.get("disks"):
                    cmd.append("--disks")
                if options.get("loggedon-users"):
                    cmd.append("--loggedon-users")
                if options.get("rid-brute"):
                    cmd.append("--rid-brute")
                if options.get("pass-pol"):
                    cmd.append("--pass-pol")
                
            elif protocol == "ldap":
                if options.get("users"):
                    cmd.append("--users")
                if options.get("groups"):
                    cmd.append("--groups")
                if options.get("computers"):
                    cmd.append("--computers")
                if options.get("trusted-for-delegation"):
                    cmd.append("--trusted-for-delegation")
                    
            elif protocol == "mssql":
                if options.get("query"):
                    cmd.extend(["--query", options["query"]])
                    
            elif protocol == "winrm":
                if options.get("exec-command"):
                    cmd.extend(["-x", options["exec-command"]])
                    
        output = run_cmd(cmd)
        
        # Parsing des résultats selon le protocole
        parsed_results = None
        if protocol == "smb":
            parsed_results = self._parse_smb_output(output)
            if username and password and "[+]" in str(output):
                self.valid_credentials.append({
                    "username": username,
                    "password": password,
                    "protocol": protocol,
                    "timestamp": datetime.now().isoformat()
                })
        elif protocol == "ldap":
            parsed_results = self._parse_ldap_output(output)
            
        self.results[protocol] = {
            "raw_output": output,
            "parsed": parsed_results
        }
        
        return parsed_results if parsed_results else output

    def check_guest_login(self, target):
        """Vérifie si le login guest est autorisé"""
        print("[*] Test du login guest...")
        
        # Création du fichier de log
        timestamp = datetime.now().strftime("%H%M%S")
        log_file = os.path.join(self.raw_logs_dir, f"guest_check_log_{timestamp}.txt")
        
        cmd = ["nxc", "smb", target, "-u", "", "-p", "", "--shares"]
        
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
            
            output_lines = []
            guest_allowed = False
            access_denied = False
            shares = []
            
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                    
                if line:
                    line = line.strip()
                    print(line)
                    f.write(f"{line}\n")
                    f.flush()
                    output_lines.append(line)
                    
                    if "[+]" in line and "\\:" in line:
                        guest_allowed = True
                    elif "STATUS_ACCESS_DENIED" in line:
                        access_denied = True
                    elif "SHARE" in line and "READ" in line:
                        share_match = re.search(r"\\\\.*\\(.*?)\s+.*?\s+(.*?)$", line)
                        if share_match:
                            share_name, share_type = share_match.groups()
                            shares.append({
                                "name": share_name.strip(),
                                "type": share_type.strip(),
                                "readable": "READ" in line,
                                "writable": "WRITE" in line
                            })
            
            for line in process.stderr:
                line = line.strip()
                print(f"[!] {line}")
                f.write(f"[!] {line}\n")
                f.flush()
        
        # Sauvegarde des résultats
        results = {
            "timestamp": datetime.now().isoformat(),
            "target": target,
            "guest_allowed": guest_allowed,
            "access_denied": access_denied,
            "shares": shares,
            "log_file": log_file
        }
        
        results_file = os.path.join(self.parsed_dir, f"guest_check_{timestamp}.json")
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=4)
        
        print(f"[+] Log complet sauvegardé dans {log_file}")
        print(f"[+] Résultats sauvegardés dans {results_file}")
        
        return results

    def analyze_target(self, target):
        """Analyse complète de la cible"""
        results = {
            "timestamp": datetime.now().isoformat(),
            "target": target,
            "vulnerabilities": [],
            "valid_users": [],
            "valid_credentials": [],
            "shares": [],
            "domain_info": {},
            "guest_access": None,
            "spider_results": None
        }

        # 1. Test du login guest
        guest_results = self.check_guest_login(target)
        results["guest_access"] = guest_results
        
        # 2. Test connexion anonyme SMB
        print("[*] Test de connexion anonyme SMB...")
        smb_anon = self.scan(target, protocol="smb", username='', password='', 
                            options={"shares": True})
        
        # Ajout des résultats SMB
        if smb_anon:
            results["shares"] = smb_anon.get("shares", [])
            results["signing"] = smb_anon.get("signing")
            results["guest_allowed"] = smb_anon.get("guest_allowed")
            results["null_session"] = smb_anon.get("null_session")

        # 3. Énumération des partages si on a des credentials
        if self.valid_credentials:
            cred = self.valid_credentials[0]
            spider_results = self.spider_plus(target, cred["username"], cred["password"])
            if spider_results and spider_results.get("results"):
                results["spider_results"] = spider_results["results"]

        # 4. Vérification de la politique de mot de passe si on a des credentials
        if self.valid_credentials:
            cred = self.valid_credentials[0]
            print("[*] Vérification de la politique de mot de passe...")
            pass_pol = self.scan(target, protocol="smb",
                               username=cred["username"],
                               password=cred["password"],
                               options={"pass-pol": True})
            if pass_pol:
                results["password_policy"] = pass_pol

        results["valid_users"] = list(self.valid_users)
        results["valid_credentials"] = self.valid_credentials
        
        return results

    def enum_shares(self, target, username=None, password=None):
        """Énumération détaillée des partages SMB"""
        return self.scan(target, protocol="smb", username=username, password=password, 
                        options={"shares": True})

    def enum_users(self, target, username=None, password=None):
        """Énumération des utilisateurs via LDAP"""
        return self.scan(target, protocol="ldap", username=username, password=password,
                        options={"users": True})

    def check_protocols(self, target, username=None, password=None):
        """Vérifie tous les protocoles supportés sur la cible"""
        results = {}
        for protocol in self.supported_protocols:
            print(f"[*] Test du protocole {protocol}...")
            results[protocol] = self.scan(target, protocol=protocol, 
                                        username=username, password=password)
        return results

    def password_spray(self, target, userlist, password, protocol="smb"):
        """Password spraying sur la cible"""
        if isinstance(userlist, str):
            with open(userlist) as f:
                userlist = [line.strip() for line in f]
                
        print(f"[*] Lancement du password spraying avec {len(userlist)} utilisateurs...")
        return self.scan(target, protocol=protocol, username=userlist, password=password)

    def brute_force(self, target, username, passlist, protocol="smb"):
        """Brute force sur un utilisateur spécifique"""
        if isinstance(passlist, str):
            with open(passlist) as f:
                passlist = [line.strip() for line in f]
                
        print(f"[*] Lancement du bruteforce pour {username} avec {len(passlist)} mots de passe...")
        return self.scan(target, protocol=protocol, username=username, password=passlist)

    def get_results(self):
        """Retourne les résultats de tous les scans effectués"""
        return {
            "scan_results": self.results,
            "vulnerabilities": self.vulnerabilities,
            "valid_users": list(self.valid_users),
            "valid_credentials": self.valid_credentials,
            "shares": self.shares,
            "domain_info": self.domain_info
        }

class NetExecModule(NetexecModule):
    """Classe wrapper pour assurer la compatibilité avec le nouveau code"""
    
    def detect_domain(self, target):
        """
        Detecte le domaine AD de la cible
        Implémenté pour être compatible avec la nouvelle structure
        """
        domain_info = super().detect_domain(target)
        
        # Sauvegarde des informations pour les autres méthodes
        self.domain_info = domain_info
        
        return domain_info
