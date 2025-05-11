class KerberosAnalyzer:
    def __init__(self, vuln_manager):
        """
        Analyseur des vulnérabilités Kerberos
        
        Args:
            vuln_manager: Référence au gestionnaire de vulnérabilités principal
        """
        self.vuln_manager = vuln_manager
        
    def analyze(self, results):
        """
        Analyse les vulnérabilités Kerberos
        
        Args:
            results: Résultats de l'analyse Kerberos
        """
        if not results:
            return
            
        # Détection AS-REP Roasting
        self._analyze_asrep_roasting(results)
        
        # Détection Kerberoasting
        self._analyze_kerberoasting(results)
        
        # Détection PreAuth non requis
        self._analyze_preauth_not_required(results)
        
        # Analyse des TGTs
        self._analyze_ticket_lifetime(results)
        
    def _analyze_asrep_roasting(self, results):
        """Analyse des comptes vulnérables à l'AS-REP Roasting"""
        if results.get("as_rep_roasting"):
            vulnerable_accounts = results.get("as_rep_users", ["Unknown"])
            
            for account in vulnerable_accounts:
                self.vuln_manager.add_vulnerability(
                    title=f"AS-REP Roasting Possible: {account}",
                    asset_value=self.vuln_manager.target,
                    target=f"kerberos://{self.vuln_manager.target}",
                    module="kerbrute",
                    type=1,  # NETWORK
                    protocol=0,  # TCP
                    port=88,  # KERBEROS
                    techno_value="Kerberos"
                )
            
    def _analyze_kerberoasting(self, results):
        """Analyse des comptes vulnérables au Kerberoasting"""
        if results.get("kerberoastable"):
            vulnerable_spns = results.get("kerberoast_spns", ["Unknown"])
            
            for spn in vulnerable_spns:
                self.vuln_manager.add_vulnerability(
                    title=f"Kerberoasting Possible: {spn}",
                    asset_value=self.vuln_manager.target,
                    target=f"kerberos://{self.vuln_manager.target}",
                    module="bloodhound",
                    type=1,  # NETWORK
                    protocol=0,  # TCP
                    port=88,  # KERBEROS
                    techno_value="Kerberos"
                )
                
    def _analyze_preauth_not_required(self, results):
        """Analyse des comptes ne nécessitant pas de pré-authentification"""
        if results.get("preauth_not_required"):
            accounts = results.get("preauth_not_required_users", ["Unknown"])
            
            for account in accounts:
                self.vuln_manager.add_vulnerability(
                    title=f"Pre-Authentication Not Required: {account}",
                    asset_value=self.vuln_manager.target,
                    target=f"kerberos://{self.vuln_manager.target}",
                    module="kerbrute",
                    type=1,  # NETWORK
                    protocol=0,  # TCP
                    port=88,  # KERBEROS
                    techno_value="Kerberos"
                )
                
    def _analyze_ticket_lifetime(self, results):
        """Analyse des problèmes liés à la durée de vie des tickets Kerberos"""
        if results.get("ticket_lifetime"):
            ticket_info = results.get("ticket_lifetime", {})
            
            # Vérification de la durée de vie trop longue des TGTs
            if ticket_info.get("tgt_lifetime", 0) > 10:  # Plus de 10 heures
                self.vuln_manager.add_vulnerability(
                    title=f"Long TGT Lifetime: {ticket_info.get('tgt_lifetime')} hours",
                    asset_value=self.vuln_manager.target,
                    target=f"kerberos://{self.vuln_manager.target}",
                    module="kerbrute",
                    type=1,  # NETWORK
                    protocol=0,  # TCP
                    port=88,  # KERBEROS
                    techno_value="Kerberos"
                )
                
            # Vérification du renouvellement des tickets trop long
            if ticket_info.get("renew_lifetime", 0) > 7*24:  # Plus de 7 jours
                self.vuln_manager.add_vulnerability(
                    title=f"Long Ticket Renewal Time: {ticket_info.get('renew_lifetime')} hours",
                    asset_value=self.vuln_manager.target,
                    target=f"kerberos://{self.vuln_manager.target}",
                    module="kerbrute",
                    type=1,  # NETWORK
                    protocol=0,  # TCP
                    port=88,  # KERBEROS
                    techno_value="Kerberos"
                ) 