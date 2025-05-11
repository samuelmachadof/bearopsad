# main.py
from config import load_config
from modules import netexec, kerbrute, bloodhound, pypykatz, certipy, responder
from modules.vuln_manager import VulnManager
import sys
import time
import os
from pathlib import Path
import json
from datetime import datetime
from threading import Thread
from queue import Queue
import logging
import configparser
from utils import detect_domain
from modules.netexec import NetExecModule
from modules.bloodhound import BloodhoundModule
from modules.certipy import CertipyModule

class PentestAD:
    def __init__(self):
        self.config = None
        self.config_file = None
        self.output_dir = None
        self.base_output_dir = None
        self.raw_logs_dir = None
        self.parsed_dir = None
        self.results_file = None
        self.domain = None
        self.target = None
        self.dc_hostname = None
        self.username = None
        self.password = None
        self.laps = None
        self.admin_count = None
        self.shares = None
        self.bloodhound_data = None
        self.vuln_manager = VulnManager()
        self.netexec = NetExecModule()
        self.bloodhound = BloodhoundModule()
        self.certipy = CertipyModule()
        self.shadow_creds_results = None
        self.wordlists = {}
        self.credentials = []
        self.modules_config = None
        self.netexec_module = netexec.NetexecModule()
        self.kerbrute_module = kerbrute.KerbruteModule()
        self.bloodhound_module = bloodhound.BloodhoundModule()
        self.responder_module = responder.ResponderModule()
        self.results_dir = "results"
        self.current_session = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results_queue = Queue()
        
    def setup_session(self):
        """Configure la session de pentest"""
        session_dir = os.path.join(self.results_dir, self.current_session)
        raw_logs_dir = os.path.join(session_dir, "raw_logs")
        parsed_dir = os.path.join(session_dir, "parsed")
        
        # Création des dossiers
        os.makedirs(session_dir, exist_ok=True)
        os.makedirs(raw_logs_dir, exist_ok=True)
        os.makedirs(parsed_dir, exist_ok=True)
        
        # Enregistrer les chemins
        self.output_dir = session_dir
        self.raw_logs_dir = raw_logs_dir
        self.parsed_dir = parsed_dir
        
        # Configuration des modules
        self.netexec_module.set_output_dir(session_dir, raw_logs_dir, parsed_dir)
        self.kerbrute_module.set_output_dir(session_dir, raw_logs_dir, parsed_dir)
        self.bloodhound_module.set_output_dir(session_dir, raw_logs_dir, parsed_dir)
        self.certipy.set_output_dir(session_dir, raw_logs_dir, parsed_dir)
        self.vuln_manager.set_output_dir(session_dir, raw_logs_dir, parsed_dir)
        
        return session_dir

    def save_output(self, phase, output, filename=None, is_raw=False):
        """Sauvegarde la sortie d'une commande"""
        session_dir = os.path.join(self.results_dir, self.current_session)
        target_dir = os.path.join(session_dir, "raw_logs" if is_raw else "parsed")
        
        if not filename:
            filename = f"{phase}_{datetime.now().strftime('%H%M%S')}.txt"
        
        filepath = os.path.join(target_dir, filename)
        with open(filepath, 'w') as f:
            if isinstance(output, str):
                f.write(output)
            else:
                json.dump(output, f, indent=4)
        print(f"[*] Résultats sauvegardés dans {filepath}")
        
    def load_config(self):
        """Charge la configuration"""
        print("[*] Chargement de la configuration...")
        self.config = load_config()
        self.target = self.config["target"]
        self.wordlists = self.config["wordlists"]
        self.credentials = self.config.get("credentials", [])
        
    def phase_1_domain_detection(self):
        """
        Phase 1: Domain detection using NetExec
        """
        print("[*] Phase 1: Domain detection")
        if self.target:
            domain_info = self.netexec.detect_domain(self.target)
            if domain_info and domain_info.get("domain"):
                self.domain = domain_info["domain"]
                self.dc_hostname = domain_info.get("hostname")
                print(f"[+] Detected domain: {self.domain}")
                print(f"[+] DC hostname: {self.dc_hostname}")
                
                # Save phase 1 results
                self.save_output("domain_detection", domain_info, "phase1_domain_detection.json")
                return domain_info
            else:
                print("[!] Failed to detect domain")
        else:
            print("[!] No target specified")
        return None

    def phase_user_enum_thread(self):
        """Thread pour l'énumération des utilisateurs"""
        print("\n[*] Phase 2: Énumération des utilisateurs avec Kerbrute")
        
        if not os.path.exists(self.wordlists["users"]):
            print("[!] Wordlist utilisateurs non trouvée")
            self.results_queue.put(("user_enum", None))
            return
            
        users = self.kerbrute_module.enum_users(self.target, self.wordlists["users"], self.domain)
        self.results_queue.put(("user_enum", users))

    def phase_share_enum_thread(self, credentials):
        """Thread pour l'énumération des partages"""
        print("\n[*] Phase 3: Énumération des partages")
        
        for cred in credentials:
            print(f"\n[*] Test des credentials {cred['user']}")
            spider_results = self.netexec_module.spider_plus(
                self.target, cred["user"], cred["pass"])
                
            if spider_results["json_path"]:
                print("[+] Énumération des partages réussie")
                self.results_queue.put(("share_enum", spider_results))
                return
                
        print("[!] Aucun accès aux partages trouvé")
        self.results_queue.put(("share_enum", None))

    def phase_bloodhound_thread(self, creds):
        """Thread pour la collecte Bloodhound"""
        print("\n[*] Phase: Collecte Bloodhound")
        
        # Extraction du hostname depuis domain_info
        dc_hostname = self.netexec_module.domain_info.get("hostname")
        if not dc_hostname:
            print("[!] Impossible de déterminer le hostname du DC")
            self.results_queue.put(("bloodhound", None))
            return
            
        results = self.bloodhound_module.run_collection(
            target_ip=self.target,
            domain=self.domain,
            username=creds["user"],
            password=creds["pass"],
            dc_hostname=dc_hostname
        )
        
        self.results_queue.put(("bloodhound", results))

    def analyze_domain_detection(self, domain_info):
        """Analyse les résultats de la détection du domaine"""
        if not domain_info:
            return
            
        # Configuration de la cible dans le gestionnaire de vulnérabilités
        self.vuln_manager.set_target(self.target, self.domain)
        
        # Analyse de l'infrastructure
        self.vuln_manager.analyze_infrastructure({
            "os": domain_info.get("os"),
            "hostname": domain_info.get("hostname")
        })

    def analyze_guest_check(self, guest_info):
        """Analyse les résultats du test de login guest"""
        if not guest_info:
            return
            
        if guest_info.get("guest_allowed"):
            self.vuln_manager.add_vulnerability(
                title="Anonymous/Guest SMB Access",
                asset_value=self.target,
                target=f"smb://{self.target}",
                module="netexec",
                type=1,  # NETWORK
                protocol=0,  # TCP
                port=445,
                techno_value="SMB"
            )
            
            # Si des partages sont accessibles, on ajoute une vulnérabilité pour chaque partage
            for share in guest_info.get("shares", []):
                if share.get("readable"):
                    self.vuln_manager.add_vulnerability(
                        title=f"Exposed Share (readable): {share['name']}",
                        asset_value=self.target,
                        target=f"smb://{self.target}/{share['name']}",
                        module="netexec",
                        type=1,  # NETWORK
                        protocol=0,  # TCP
                        port=445,
                        techno_value="SMB"
                    )

    def analyze_user_enum(self, user_results):
        """Analyse les résultats de l'énumération des utilisateurs"""
        if not user_results:
            return
            
        # Analyse de la sécurité Kerberos
        self.vuln_manager.analyze_kerberos_security({
            "as_rep_roasting": user_results.get("valid_users", []),
            "kerberoastable": []  # Sera rempli par Bloodhound
        })

    def analyze_share_enum(self, share_results):
        """Analyse les résultats de l'énumération des partages"""
        if not share_results or not share_results.get("results"):
            return
            
        # Préparation des données pour l'analyse SMB
        shares = []
        for share_name, share_data in share_results["results"].items():
            shares.append({
                "name": share_name,
                "readable": True,  # Si on a les résultats, c'est qu'on peut lire
                "writable": share_data.get("writable", False),
                "files": share_data.get("files", []),
                "folders": share_data.get("folders", [])
            })
            
        # Analyse de la sécurité SMB
        self.vuln_manager.analyze_smb_security({
            "shares": shares
        })

    def analyze_bloodhound(self, bh_results):
        """Analyse les résultats de Bloodhound"""
        if not bh_results:
            return
            
        # Analyse des données Bloodhound
        self.vuln_manager.add_vulnerability(
            title="Active Directory Data Collected",
            asset_value=self.target,
            target=f"ldap://{self.target}",
            module="bloodhound",
            type=1,  # NETWORK
            protocol=0,  # TCP
            port=389,
            techno_value="Active Directory"
        )
        
        # Analyse approfondie des vulnérabilités avec Bloodhound
        if bh_results.get("zip_file"):
            # Ici nous devrions extraire et analyser le ZIP, mais pour simplifier
            # nous allons simuler l'analyse des données
            bloodhound_data = self._extract_bloodhound_data(bh_results.get("zip_file"))
            if bloodhound_data:
                self.vuln_manager.analyze_bloodhound_data(bloodhound_data)
    
    def _extract_bloodhound_data(self, zip_file_path):
        """Extrait et analyse les données Bloodhound du ZIP"""
        if not zip_file_path or not os.path.exists(zip_file_path):
            return None
            
        try:
            import zipfile
            import tempfile
            import json
            
            temp_dir = tempfile.mkdtemp()
            
            # Extraction du ZIP
            with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
                
            # Analyse des fichiers JSON extraits
            bloodhound_data = {
                "users": {},
                "computers": {},
                "groups": {},
                "domains": {},
                "gpos": {},
                "ous": {},
                "acls": {}
            }
            
            # Chargement des données par type
            file_mapping = {
                "users": ["*users.json"],
                "computers": ["*computers.json"],
                "groups": ["*groups.json"],
                "domains": ["*domains.json"],
                "gpos": ["*gpos.json"],
                "ous": ["*ous.json"]
            }
            
            import glob
            for data_type, file_patterns in file_mapping.items():
                for pattern in file_patterns:
                    for file_path in glob.glob(os.path.join(temp_dir, pattern)):
                        try:
                            with open(file_path, 'r') as f:
                                data = json.load(f)
                                if isinstance(data, list):
                                    for item in data:
                                        if "id" in item and "properties" in item:
                                            bloodhound_data[data_type][item["id"]] = item["properties"]
                                elif isinstance(data, dict) and "data" in data:
                                    for item in data.get("data", []):
                                        if "id" in item and "properties" in item:
                                            bloodhound_data[data_type][item["id"]] = item["properties"]
                        except Exception as e:
                            print(f"[!] Erreur lors de l'analyse du fichier {file_path}: {str(e)}")
            
            # Traitement des ACLs à partir des données existantes
            for data_type in ["users", "computers", "groups", "domains", "gpos", "ous"]:
                for obj_id, obj_data in bloodhound_data[data_type].items():
                    if "acl" in obj_data:
                        bloodhound_data["acls"][obj_id] = obj_data["acl"]
                        
            return bloodhound_data
            
        except Exception as e:
            print(f"[!] Erreur lors de l'extraction des données Bloodhound: {str(e)}")
            return None
            
    def analyze_shadow_credentials(self, results):
        """Analyse les résultats de Shadow Credentials"""
        if not results:
            return
            
        # Passer les résultats au VulnManager pour analyse approfondie
        self.vuln_manager.analyze_shadow_credentials(results)

    def phase_3_bloodhound(self):
        """
        Phase 3: Bloodhound data collection
        Collects data using BloodHound
        """
        print("[*] Phase 3: Bloodhound data collection")
        if self.domain and self.target and self.username and self.password:
            self.bloodhound.set_output_dir(self.output_dir, self.raw_logs_dir, self.parsed_dir)
            self.bloodhound_data = self.bloodhound.collect_data(self.target, self.domain, self.username, self.password)
            print(f"[+] Bloodhound data collection completed")
            
            # Save phase 3 results
            self.save_output("bloodhound", self.bloodhound_data, "phase3_bloodhound.json")
        else:
            print("[!] Missing parameters for Bloodhound data collection")
    
    def phase_4_shadow_credentials(self):
        """
        Phase 4: Test de Shadow Credentials Attack
        Vérifie les vulnérabilités liées aux Shadow Credentials
        """
        print("[*] Phase 4: Test de Shadow Credentials Attack")
        if self.domain and self.target and self.username and self.password and self.dc_hostname:
            self.certipy.set_output_dir(self.output_dir, self.raw_logs_dir, self.parsed_dir)
            self.shadow_creds_results = self.certipy.test_shadow_credentials(
                self.target, 
                self.domain, 
                self.username, 
                self.password, 
                self.dc_hostname
            )
            
            # Ajouter les vulnérabilités trouvées au gestionnaire de vulnérabilités
            if self.shadow_creds_results and self.shadow_creds_results.get("vulnerable_targets"):
                for target_info in self.shadow_creds_results.get("vulnerable_targets", []):
                    self.vuln_manager.add_vulnerability(
                        name="Shadow Credentials", 
                        description=f"Le compte {target_info['name']} est vulnérable à l'attaque Shadow Credentials",
                        impact="High",
                        mitigation="Vérifier et corriger les ACLs sur l'attribut msDS-KeyCredentialLink",
                        affected=target_info['name'],
                        details=target_info
                    )
            
            # Sauvegarder les résultats de la phase 4
            self.save_output("shadow_credentials", self.shadow_creds_results, "phase4_shadow_credentials.json")
            print(f"[+] Test Shadow Credentials terminé")
        else:
            print("[!] Paramètres manquants pour le test Shadow Credentials")

    def analyze_results(self):
        """Analyse les résultats de la phase 3 et 4"""
        if self.bloodhound_data:
            self.analyze_bloodhound(self.bloodhound_data)
            self.vuln_manager.save_vulnerabilities()
        
        if self.shadow_creds_results:
            self.analyze_shadow_credentials(self.shadow_creds_results)
            self.vuln_manager.save_vulnerabilities()

    def run(self):
        """Exécution principale"""
        try:
            # Configuration initiale
            self.load_config()
            session_dir = self.setup_session()
            
            print(f"\n[*] Cible: {self.target}")
            
            # Phase 1: Détection du domaine (synchrone)
            domain_info = self.phase_1_domain_detection()
            
            # Configuration du VulnManager
            self.vuln_manager.set_target(self.target, self.domain)
            
            # Analyse immédiate de l'infrastructure
            self.analyze_domain_detection(domain_info)
            self.vuln_manager.save_vulnerabilities()
            
            # Phase 2: Test du login guest (synchrone)
            guest_info = self.netexec_module.check_guest_login(self.target)
            
            # Analyse immédiate du guest login
            self.analyze_guest_check(guest_info)
            self.vuln_manager.save_vulnerabilities()
            
            # Analyse SMB initiale
            smb_results = {
                "guest_allowed": guest_info.get("guest_allowed"),
                "access_denied": guest_info.get("access_denied"),
                "signing": domain_info.get("signing"),
                "shares": []
            }
            self.vuln_manager.analyze_smb_security(smb_results)
            self.vuln_manager.save_vulnerabilities()
            
            # Lancement des phases en parallèle
            threads = []
            
            # Thread pour Kerbrute
            kerbrute_thread = Thread(target=self.phase_user_enum_thread)
            kerbrute_thread.start()
            threads.append(kerbrute_thread)
            
            # Thread pour Spider_plus si on a des credentials
            if self.credentials:
                spider_thread = Thread(target=self.phase_share_enum_thread, args=(self.credentials,))
                spider_thread.start()
                threads.append(spider_thread)
                
                # Lancement de Bloodhound si on a des credentials
                bloodhound_thread = Thread(target=self.phase_bloodhound_thread, args=(self.credentials[0],))
                bloodhound_thread.start()
                threads.append(bloodhound_thread)
            
            # Attente de la fin des threads
            results = {
                "domain_detection": domain_info,
                "guest_check": guest_info,
                "user_enum": None,
                "share_enum": None,
                "bloodhound": None
            }
            
            # Récupération des résultats
            for _ in range(len(threads)):
                phase, result = self.results_queue.get()
                results[phase] = result
                
                # Analyse immédiate des résultats pour les vulnérabilités
                if phase == "user_enum":
                    self.analyze_user_enum(result)
                    self.vuln_manager.save_vulnerabilities()
                elif phase == "share_enum":
                    self.analyze_share_enum(result)
                    self.vuln_manager.save_vulnerabilities()
                elif phase == "bloodhound":
                    self.analyze_bloodhound(result)
                    self.vuln_manager.save_vulnerabilities()
            
            # Attente de la fin de tous les threads
            for thread in threads:
                thread.join()
            
            # Sauvegarde finale des résultats
            final_results = {
                "target": self.target,
                "domain": self.domain,
                "timestamp": self.current_session,
                "phases": results
            }
            self.save_output("final", final_results)
            
            # Phase 3: Bloodhound data collection
            self.phase_3_bloodhound()
            
            # Phase 4: Shadow Credentials test
            self.phase_4_shadow_credentials()
            
            # Analyze results
            self.analyze_results()
            
        except KeyboardInterrupt:
            print("\n[!] Interruption par l'utilisateur")
            sys.exit(1)
        except Exception as e:
            print(f"\n[!] Erreur: {str(e)}")
            sys.exit(1)

if __name__ == "__main__":
    pentest = PentestAD()
    pentest.run()
