class LDAPAnalyzer:
    def __init__(self, vuln_manager):
        """
        Analyseur des vulnérabilités LDAP
        
        Args:
            vuln_manager: Référence au gestionnaire de vulnérabilités principal
        """
        self.vuln_manager = vuln_manager
        
    def analyze(self, results):
        """
        Analyse les vulnérabilités LDAP
        
        Args:
            results: Résultats de l'analyse LDAP
        """
        if not results:
            return
            
        # Vérification des liaisons anonymes
        self._analyze_anonymous_bind(results)
        
        # Vérification de l'authentification en clair
        self._analyze_cleartext_auth(results)
        
        # Vérification du chiffrement LDAP
        self._analyze_ldap_encryption(results)
        
        # Vérification des groupes sensibles
        self._analyze_sensitive_groups(results)
        
    def _analyze_anonymous_bind(self, results):
        """Analyse la possibilité de liaison LDAP anonyme"""
        if results.get("anonymous_bind"):
            self.vuln_manager.add_vulnerability(
                title="LDAP Anonymous Bind Allowed",
                asset_value=self.vuln_manager.target,
                target=f"ldap://{self.vuln_manager.target}",
                module="netexec",
                type=1,  # NETWORK
                protocol=0,  # TCP
                port=389,  # LDAP
                techno_value="LDAP"
            )
            
    def _analyze_cleartext_auth(self, results):
        """Analyse l'authentification LDAP en clair"""
        if results.get("cleartext_auth"):
            self.vuln_manager.add_vulnerability(
                title="LDAP Cleartext Authentication",
                asset_value=self.vuln_manager.target,
                target=f"ldap://{self.vuln_manager.target}",
                module="netexec",
                type=1,  # NETWORK
                protocol=0,  # TCP
                port=389,  # LDAP
                techno_value="LDAP"
            )
            
    def _analyze_ldap_encryption(self, results):
        """Analyse le chiffrement LDAP (TLS/SSL)"""
        if results.get("encryption_details"):
            encryption = results.get("encryption_details", {})
            
            # Vérification de LDAP sans StartTLS ou LDAPS
            if not encryption.get("starttls_supported") and not encryption.get("ldaps_supported"):
                self.vuln_manager.add_vulnerability(
                    title="LDAP Without Encryption",
                    asset_value=self.vuln_manager.target,
                    target=f"ldap://{self.vuln_manager.target}",
                    module="netexec",
                    type=1,  # NETWORK
                    protocol=0,  # TCP
                    port=389,  # LDAP
                    techno_value="LDAP"
                )
                
            # Vérification de TLS avec chiffrement faible
            if encryption.get("weak_ciphers") or encryption.get("obsolete_protocols"):
                self.vuln_manager.add_vulnerability(
                    title="LDAP Weak Encryption Configuration",
                    asset_value=self.vuln_manager.target,
                    target=f"ldap://{self.vuln_manager.target}",
                    module="netexec",
                    type=1,  # NETWORK
                    protocol=0,  # TCP
                    port=389,  # LDAP
                    techno_value="LDAP"
                )
                
    def _analyze_sensitive_groups(self, results):
        """Analyse des groupes sensibles exposés via LDAP"""
        if results.get("groups"):
            groups = results.get("groups", [])
            
            # Liste des groupes sensibles à surveiller
            sensitive_groups = [
                "Domain Admins", "Enterprise Admins", "Schema Admins", 
                "Administrators", "Account Operators", "Backup Operators",
                "Print Operators", "Server Operators", "Domain Controllers",
                "Group Policy Creator Owners", "DNSAdmins", "DHCP Administrators"
            ]
            
            # Vérifier chaque groupe sensible trouvé
            for group in groups:
                if any(sensitive in group for sensitive in sensitive_groups):
                    self.vuln_manager.add_vulnerability(
                        title=f"Sensitive Group Exposed: {group}",
                        asset_value=self.vuln_manager.target,
                        target=f"ldap://{self.vuln_manager.target}",
                        module="netexec",
                        type=1,  # NETWORK
                        protocol=0,  # TCP
                        port=389,  # LDAP
                        techno_value="LDAP"
                    )
                    
            # Vérification spécifique des groupes protégés
            protected_users_found = any("Protected Users" in group for group in groups)
            if not protected_users_found:
                self.vuln_manager.add_vulnerability(
                    title="No Protected Users Group Found",
                    asset_value=self.vuln_manager.target,
                    target=f"ldap://{self.vuln_manager.target}",
                    module="netexec",
                    type=1,  # NETWORK
                    protocol=0,  # TCP
                    port=389,  # LDAP
                    techno_value="LDAP"
                ) 