import os

class SMBAnalyzer:
    def __init__(self, vuln_manager):
        """
        Analyseur des vulnérabilités SMB
        
        Args:
            vuln_manager: Référence au gestionnaire de vulnérabilités principal
        """
        self.vuln_manager = vuln_manager
        
    def analyze(self, results):
        """
        Analyse les vulnérabilités SMB
        
        Args:
            results: Résultats de l'analyse SMB
        """
        if not results:
            return
            
        # Vérification de la signature SMB
        self._analyze_smb_signing(results)
        
        # Vérification de l'accès guest/anonymous
        self._analyze_guest_access(results)
        
        # Analyse des partages accessibles
        self._analyze_exposed_shares(results)
        
        # Analyse des fichiers sensibles dans les partages
        self._analyze_sensitive_files(results)
        
    def _analyze_smb_signing(self, results):
        """Analyse la configuration de la signature SMB"""
        if results.get("signing") is False:
            self.vuln_manager.add_vulnerability(
                title="SMB Signing Not Required",
                asset_value=self.vuln_manager.target,
                target=f"smb://{self.vuln_manager.target}",
                module="netexec",
                type=1,  # NETWORK
                protocol=0,  # TCP
                port=445,  # SMB
                techno_value="SMB"
            )
            
    def _analyze_guest_access(self, results):
        """Analyse l'accès guest ou anonymous"""
        if results.get("guest_allowed") or results.get("null_session"):
            self.vuln_manager.add_vulnerability(
                title="Anonymous/Guest SMB Access",
                asset_value=self.vuln_manager.target,
                target=f"smb://{self.vuln_manager.target}",
                module="netexec",
                type=1,  # NETWORK
                protocol=0,  # TCP
                port=445,  # SMB
                techno_value="SMB"
            )
            
    def _analyze_exposed_shares(self, results):
        """Analyse les partages exposés"""
        if not results.get("shares"):
            return
            
        for share in results["shares"]:
            share_name = share["name"].lower()
            if share_name not in ["c$", "admin$", "ipc$"]:
                # Partage accessible
                if share.get("readable") or share.get("writable"):
                    access_type = "writable" if share.get("writable") else "readable"
                    self.vuln_manager.add_vulnerability(
                        title=f"Exposed Share ({access_type}): {share['name']}",
                        asset_value=self.vuln_manager.target,
                        target=f"smb://{self.vuln_manager.target}/{share['name']}",
                        module="netexec",
                        type=1,  # NETWORK
                        protocol=0,  # TCP
                        port=445,  # SMB
                        techno_value="SMB"
                    )
                    
    def _analyze_sensitive_files(self, results):
        """Analyse les fichiers sensibles dans les partages"""
        if not results.get("spider_results"):
            return
            
        spider_data = results["spider_results"]
        for share_name, share_data in spider_data.items():
            if share_name.lower() not in ["c$", "admin$", "ipc$"]:
                self._scan_for_sensitive_files(share_name, share_data)
                
    def _scan_for_sensitive_files(self, share_name, share_data):
        """Recherche des fichiers sensibles dans un partage"""
        sensitive_extensions = {
            # Documents
            ".doc": "Word Document",
            ".docx": "Word Document",
            ".xls": "Excel Spreadsheet",
            ".xlsx": "Excel Spreadsheet",
            ".ppt": "PowerPoint Presentation",
            ".pptx": "PowerPoint Presentation",
            ".pdf": "PDF Document",
            
            # Configuration et données
            ".config": "Configuration File",
            ".ini": "Configuration File",
            ".xml": "XML Data",
            ".json": "JSON Data",
            ".yaml": "YAML Configuration",
            ".yml": "YAML Configuration",
            
            # Bases de données
            ".db": "Database File",
            ".sqlite": "SQLite Database",
            ".mdb": "Access Database",
            ".accdb": "Access Database",
            ".bak": "Backup File",
            
            # Scripts et code
            ".ps1": "PowerShell Script",
            ".bat": "Batch Script",
            ".vbs": "Visual Basic Script",
            ".sh": "Shell Script",
            
            # Données sensibles
            ".pfx": "Certificate File",
            ".cer": "Certificate File",
            ".key": "Private Key",
            ".pem": "Certificate/Key File",
            ".kdbx": "KeePass Database",
            ".kdb": "KeePass Database",
            ".rdp": "Remote Desktop Connection"
        }
        
        # Noms de fichiers sensibles
        sensitive_filenames = [
            "password", "passwd", "credentials", "account", "secret", 
            "confidential", "private", "secure", "admin", "root",
            "backup", "config", "configuration"
        ]
        
        for file_path in share_data.get("files", []):
            file_name = os.path.basename(file_path).lower()
            file_ext = os.path.splitext(file_name)[1].lower()
            
            # Vérification de l'extension
            if file_ext in sensitive_extensions:
                self.vuln_manager.add_vulnerability(
                    title=f"Sensitive File ({sensitive_extensions[file_ext]}): {file_name}",
                    asset_value=self.vuln_manager.target,
                    target=f"smb://{self.vuln_manager.target}/{share_name}/{file_path}",
                    module="netexec",
                    type=1,  # NETWORK
                    protocol=0,  # TCP
                    port=445,  # SMB
                    techno_value="SMB"
                )
                continue
                
            # Vérification du nom de fichier
            if any(sensitive in file_name for sensitive in sensitive_filenames):
                self.vuln_manager.add_vulnerability(
                    title=f"Potentially Sensitive File: {file_name}",
                    asset_value=self.vuln_manager.target,
                    target=f"smb://{self.vuln_manager.target}/{share_name}/{file_path}",
                    module="netexec",
                    type=1,  # NETWORK
                    protocol=0,  # TCP
                    port=445,  # SMB
                    techno_value="SMB"
                ) 