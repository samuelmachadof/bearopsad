class InfrastructureAnalyzer:
    def __init__(self, vuln_manager):
        """
        Analyseur des vulnérabilités d'infrastructure
        
        Args:
            vuln_manager: Référence au gestionnaire de vulnérabilités principal
        """
        self.vuln_manager = vuln_manager
        
    def analyze(self, results):
        """
        Analyse les vulnérabilités d'infrastructure
        
        Args:
            results: Résultats de l'analyse d'infrastructure
        """
        if not results:
            return
            
        # Vérification de la version de l'OS
        self._analyze_os_version(results)
        
        # Vérification de la politique de mots de passe
        self._analyze_password_policy(results)
        
        # Vérification des correctifs de sécurité
        self._analyze_missing_patches(results)
        
        # Vérification des services exposés
        self._analyze_exposed_services(results)
        
    def _analyze_os_version(self, results):
        """Analyse la version de l'OS pour détecter les systèmes obsolètes"""
        if results.get("os"):
            os_info = results.get("os")
            outdated_systems = ["windows 7", "windows server 2008", "windows server 2003", 
                                "windows xp", "windows vista", "windows 2000"]
                                
            if any(system in os_info.lower() for system in outdated_systems):
                self.vuln_manager.add_vulnerability(
                    title="Outdated Operating System",
                    asset_value=self.vuln_manager.target,
                    target=f"smb://{self.vuln_manager.target}",
                    module="netexec",
                    type=1,  # NETWORK
                    protocol=0,  # TCP
                    port=445,  # SMB
                    techno_value="Windows",
                    version=os_info
                )
                
    def _analyze_password_policy(self, results):
        """Analyse la politique de mots de passe pour détecter les configurations faibles"""
        if results.get("password_policy"):
            policy = results.get("password_policy")
            
            weak_policy = False
            weakness_details = []
            
            # Vérification de la longueur minimale
            if policy.get("min_length", 0) < 12:
                weak_policy = True
                weakness_details.append(f"Minimum password length is only {policy.get('min_length')} characters")
                
            # Vérification de la complexité
            if not policy.get("complexity"):
                weak_policy = True
                weakness_details.append("Password complexity not required")
                
            # Vérification de l'âge maximal
            if policy.get("max_age", 0) > 90:
                weak_policy = True
                weakness_details.append(f"Password max age is {policy.get('max_age')} days")
                
            # Vérification de l'historique
            if policy.get("history_length", 0) < 10:
                weak_policy = True
                weakness_details.append(f"Password history is only {policy.get('history_length')} passwords")
                
            if weak_policy:
                self.vuln_manager.add_vulnerability(
                    title=f"Weak Password Policy: {', '.join(weakness_details)}",
                    asset_value=self.vuln_manager.target,
                    target=f"ldap://{self.vuln_manager.target}",
                    module="netexec",
                    type=1,  # NETWORK
                    protocol=0,  # TCP
                    port=389,  # LDAP
                    techno_value="Active Directory"
                )
                
    def _analyze_missing_patches(self, results):
        """Analyse les correctifs de sécurité manquants"""
        if results.get("missing_patches"):
            patches = results.get("missing_patches", [])
            
            for patch in patches:
                severity = patch.get("severity", "Unknown")
                kb = patch.get("kb", "Unknown KB")
                cves = patch.get("cves", [])
                
                # Si critique ou important
                if severity.lower() in ["critical", "important"]:
                    cve_str = ", ".join(cves) if cves else "Unknown CVEs"
                    self.vuln_manager.add_vulnerability(
                        title=f"Missing {severity} Patch: {kb} ({cve_str})",
                        asset_value=self.vuln_manager.target,
                        target=f"smb://{self.vuln_manager.target}",
                        module="netexec",
                        type=1,  # NETWORK
                        protocol=0,  # TCP
                        port=445,  # SMB
                        techno_value="Windows"
                    )
                    
    def _analyze_exposed_services(self, results):
        """Analyse les services exposés non nécessaires"""
        if results.get("services"):
            risky_services = ["telnet", "ftp", "smtp", "pop3", "imap", "snmp", "rdp", "rsh", "rlogin", "vnc"]
            services = results.get("services", {})
            
            for service_name, service_info in services.items():
                if any(risky in service_name.lower() for risky in risky_services):
                    port = service_info.get("port", 0)
                    self.vuln_manager.add_vulnerability(
                        title=f"Potentially Risky Service Exposed: {service_name}",
                        asset_value=self.vuln_manager.target,
                        target=f"tcp://{self.vuln_manager.target}:{port}",
                        module="nmap",
                        type=1,  # NETWORK
                        protocol=0,  # TCP
                        port=port,
                        techno_value=service_name
                    ) 