class DNSAnalyzer:
    def __init__(self, vuln_manager):
        """
        Analyseur des vulnérabilités DNS
        
        Args:
            vuln_manager: Référence au gestionnaire de vulnérabilités principal
        """
        self.vuln_manager = vuln_manager
        
    def analyze(self, results):
        """
        Analyse les vulnérabilités DNS
        
        Args:
            results: Résultats de l'analyse DNS
        """
        if not results:
            return
            
        # Vérification des transferts de zone
        self._analyze_zone_transfers(results)
        
        # Vérification de la configuration DNSSEC
        self._analyze_dnssec(results)
        
        # Vérification des requêtes récursives
        self._analyze_recursive_queries(results)
        
        # Vérification des enregistrements sensibles
        self._analyze_sensitive_records(results)
        
    def _analyze_zone_transfers(self, results):
        """Analyse la possibilité de transferts de zone DNS"""
        if results.get("zone_transfer_enabled"):
            zones_exposed = results.get("exposed_zones", ["all"])
            for zone in zones_exposed:
                self.vuln_manager.add_vulnerability(
                    title=f"DNS Zone Transfer Enabled for {zone}",
                    asset_value=self.vuln_manager.target,
                    target=f"dns://{self.vuln_manager.target}",
                    module="dns",
                    type=1,  # NETWORK
                    protocol=0,  # TCP/UDP
                    port=53,  # DNS
                    techno_value="DNS"
                )
                
    def _analyze_dnssec(self, results):
        """Analyse la configuration DNSSEC"""
        dnssec_info = results.get("dnssec", {})
        
        # DNSSEC non configuré
        if not dnssec_info.get("enabled"):
            self.vuln_manager.add_vulnerability(
                title="DNSSEC Not Enabled",
                asset_value=self.vuln_manager.target,
                target=f"dns://{self.vuln_manager.target}",
                module="dns",
                type=1,  # NETWORK
                protocol=0,  # TCP/UDP
                port=53,  # DNS
                techno_value="DNS"
            )
        # DNSSEC mal configuré
        elif dnssec_info.get("misconfigured"):
            self.vuln_manager.add_vulnerability(
                title="DNSSEC Misconfiguration",
                asset_value=self.vuln_manager.target,
                target=f"dns://{self.vuln_manager.target}",
                module="dns",
                type=1,  # NETWORK
                protocol=0,  # TCP/UDP
                port=53,  # DNS
                techno_value="DNS"
            )
            
    def _analyze_recursive_queries(self, results):
        """Analyse la possibilité de requêtes récursives"""
        if results.get("recursive_queries_allowed"):
            self.vuln_manager.add_vulnerability(
                title="DNS Recursive Queries Allowed",
                asset_value=self.vuln_manager.target,
                target=f"dns://{self.vuln_manager.target}",
                module="dns",
                type=1,  # NETWORK
                protocol=0,  # TCP/UDP
                port=53,  # DNS
                techno_value="DNS"
            )
            
    def _analyze_sensitive_records(self, results):
        """Analyse des enregistrements DNS sensibles"""
        records = results.get("records", [])
        
        # Vérification des enregistrements TXT sensibles (clés, tokens, etc.)
        sensitive_txt_found = False
        sensitive_patterns = ["key", "token", "password", "secret", "api", "aws", "azure", "credential"]
        
        for record in records:
            if record.get("type") == "TXT":
                txt_value = record.get("value", "").lower()
                if any(pattern in txt_value for pattern in sensitive_patterns):
                    sensitive_txt_found = True
                    self.vuln_manager.add_vulnerability(
                        title="Sensitive Information in DNS TXT Record",
                        asset_value=self.vuln_manager.target,
                        target=f"dns://{self.vuln_manager.target}",
                        module="dns",
                        type=1,  # NETWORK
                        protocol=0,  # TCP/UDP
                        port=53,  # DNS
                        techno_value="DNS"
                    )
                    break
        
        # Vérification d'enregistrements potentiellement dangereux (wildcard)
        wildcard_found = False
        for record in records:
            if record.get("name", "").startswith("*"):
                wildcard_found = True
                self.vuln_manager.add_vulnerability(
                    title="DNS Wildcard Record Found",
                    asset_value=self.vuln_manager.target,
                    target=f"dns://{self.vuln_manager.target}",
                    module="dns",
                    type=1,  # NETWORK
                    protocol=0,  # TCP/UDP
                    port=53,  # DNS
                    techno_value="DNS"
                )
                break 