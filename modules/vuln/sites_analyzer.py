class SitesAnalyzer:
    def __init__(self, vuln_manager):
        """
        Analyseur des Sites & Services Active Directory
        
        Args:
            vuln_manager: Référence au gestionnaire de vulnérabilités principal
        """
        self.vuln_manager = vuln_manager
        
    def analyze(self, results):
        """
        Analyse les Sites & Services Active Directory
        
        Args:
            results: Résultats de l'analyse des Sites & Services AD
        """
        if not results:
            return
            
        # Analyse des sites
        if results.get("sites"):
            self._analyze_sites(results.get("sites", []))
            
        # Analyse des subnets
        if results.get("subnets"):
            self._analyze_subnets(results.get("subnets", []))
            
        # Analyse des connexions entre sites
        if results.get("site_links"):
            self._analyze_site_links(results.get("site_links", []))
            
        # Analyse des contrôleurs de domaine sans site
        if results.get("domain_controllers") and results.get("sites"):
            self._analyze_dc_without_site(
                results.get("domain_controllers", []),
                results.get("sites", [])
            )
            
    def _analyze_sites(self, sites):
        """
        Analyse des sites AD
        
        Args:
            sites: Liste des sites AD
        """
        # Vérifier si le site par défaut contient des machines
        default_site = next((site for site in sites if site.get("name") == "Default-First-Site-Name"), None)
        
        if default_site and default_site.get("servers") and len(default_site.get("servers", [])) > 0:
            server_count = len(default_site.get("servers", []))
            self.vuln_manager.add_vulnerability(
                title=f"Default Site Still In Use: {server_count} servers in Default-First-Site-Name",
                asset_value=self.vuln_manager.target,
                target=f"ldap://{self.vuln_manager.target}",
                module="sites_and_services",
                type=1,  # NETWORK
                protocol=0,  # TCP
                port=389,  # LDAP
                techno_value="Active Directory"
            )
            
        # Vérifier les sites sans contrôleur de domaine
        for site in sites:
            site_name = site.get("name", "Unknown Site")
            servers = site.get("servers", [])
            dcs = [server for server in servers if server.get("is_dc", False)]
            
            if not dcs and servers:
                server_count = len(servers)
                self.vuln_manager.add_vulnerability(
                    title=f"Site Without Domain Controller: {site_name} ({server_count} non-DC servers)",
                    asset_value=self.vuln_manager.target,
                    target=f"ldap://{self.vuln_manager.target}",
                    module="sites_and_services",
                    type=1,  # NETWORK
                    protocol=0,  # TCP
                    port=389,  # LDAP
                    techno_value="Active Directory"
                )
                
        # Vérifier les sites mal configurés
        for site in sites:
            if site.get("misconfigured"):
                misconfig_details = site.get("misconfiguration_details", "Unknown misconfiguration")
                site_name = site.get("name", "Unknown Site")
                
                self.vuln_manager.add_vulnerability(
                    title=f"Misconfigured AD Site: {site_name} ({misconfig_details})",
                    asset_value=self.vuln_manager.target,
                    target=f"ldap://{self.vuln_manager.target}",
                    module="sites_and_services",
                    type=1,  # NETWORK
                    protocol=0,  # TCP
                    port=389,  # LDAP
                    techno_value="Active Directory"
                )
                
    def _analyze_subnets(self, subnets):
        """
        Analyse des sous-réseaux AD
        
        Args:
            subnets: Liste des sous-réseaux AD
        """
        # Vérifier les sous-réseaux sans site attribué
        orphaned_subnets = [subnet for subnet in subnets if not subnet.get("site")]
        
        if orphaned_subnets:
            subnet_count = len(orphaned_subnets)
            examples = ", ".join([subnet.get("prefix", "Unknown") for subnet in orphaned_subnets[:3]])
            
            self.vuln_manager.add_vulnerability(
                title=f"Orphaned Subnets: {subnet_count} subnets without site (e.g., {examples})",
                asset_value=self.vuln_manager.target,
                target=f"ldap://{self.vuln_manager.target}",
                module="sites_and_services",
                type=1,  # NETWORK
                protocol=0,  # TCP
                port=389,  # LDAP
                techno_value="Active Directory"
            )
            
        # Vérifier les sous-réseaux qui se chevauchent
        overlapping_subnets = []
        for i, subnet1 in enumerate(subnets):
            for subnet2 in subnets[i+1:]:
                if self._subnets_overlap(subnet1, subnet2):
                    overlap_pair = (subnet1.get("prefix"), subnet2.get("prefix"))
                    if overlap_pair not in overlapping_subnets:
                        overlapping_subnets.append(overlap_pair)
                        
        if overlapping_subnets:
            overlap_count = len(overlapping_subnets)
            examples = ", ".join([f"{s1} and {s2}" for s1, s2 in overlapping_subnets[:2]])
            
            self.vuln_manager.add_vulnerability(
                title=f"Overlapping Subnets: {overlap_count} subnet overlaps detected (e.g., {examples})",
                asset_value=self.vuln_manager.target,
                target=f"ldap://{self.vuln_manager.target}",
                module="sites_and_services",
                type=1,  # NETWORK
                protocol=0,  # TCP
                port=389,  # LDAP
                techno_value="Active Directory"
            )
            
    def _analyze_site_links(self, site_links):
        """
        Analyse des liens entre sites AD
        
        Args:
            site_links: Liste des liens entre sites AD
        """
        # Vérifier les liens entre sites avec des coûts très élevés
        high_cost_links = [link for link in site_links if link.get("cost", 0) > 500]
        
        if high_cost_links:
            link_count = len(high_cost_links)
            examples = ", ".join([f"{link.get('name', 'Unknown')} (cost: {link.get('cost')})" for link in high_cost_links[:3]])
            
            self.vuln_manager.add_vulnerability(
                title=f"High Cost Site Links: {link_count} links with high cost (e.g., {examples})",
                asset_value=self.vuln_manager.target,
                target=f"ldap://{self.vuln_manager.target}",
                module="sites_and_services",
                type=1,  # NETWORK
                protocol=0,  # TCP
                port=389,  # LDAP
                techno_value="Active Directory"
            )
            
        # Vérifier les intervalles de réplication longs
        long_replication_links = [link for link in site_links if link.get("replication_interval", 0) > 180]
        
        if long_replication_links:
            link_count = len(long_replication_links)
            examples = ", ".join([f"{link.get('name', 'Unknown')} (interval: {link.get('replication_interval')} min)" for link in long_replication_links[:3]])
            
            self.vuln_manager.add_vulnerability(
                title=f"Long Replication Intervals: {link_count} links with long intervals (e.g., {examples})",
                asset_value=self.vuln_manager.target,
                target=f"ldap://{self.vuln_manager.target}",
                module="sites_and_services",
                type=1,  # NETWORK
                protocol=0,  # TCP
                port=389,  # LDAP
                techno_value="Active Directory"
            )
            
    def _analyze_dc_without_site(self, domain_controllers, sites):
        """
        Analyse des contrôleurs de domaine sans site attribué
        
        Args:
            domain_controllers: Liste des contrôleurs de domaine
            sites: Liste des sites AD
        """
        # Extraire tous les serveurs des sites
        all_site_servers = []
        for site in sites:
            all_site_servers.extend([server.get("name", "").lower() for server in site.get("servers", [])])
            
        # Trouver les DC qui ne sont pas dans un site
        dc_without_site = []
        for dc in domain_controllers:
            dc_name = dc.get("name", "").lower()
            if dc_name and dc_name not in all_site_servers:
                dc_without_site.append(dc.get("name", "Unknown DC"))
                
        if dc_without_site:
            dc_count = len(dc_without_site)
            examples = ", ".join(dc_without_site[:5])
            
            self.vuln_manager.add_vulnerability(
                title=f"Domain Controllers Without Site: {dc_count} DCs not assigned to a site (e.g., {examples})",
                asset_value=self.vuln_manager.target,
                target=f"ldap://{self.vuln_manager.target}",
                module="sites_and_services",
                type=1,  # NETWORK
                protocol=0,  # TCP
                port=389,  # LDAP
                techno_value="Active Directory"
            )
            
    def _subnets_overlap(self, subnet1, subnet2):
        """
        Vérifie si deux sous-réseaux se chevauchent
        
        Args:
            subnet1: Premier sous-réseau
            subnet2: Deuxième sous-réseau
            
        Returns:
            bool: True si les sous-réseaux se chevauchent, False sinon
        """
        try:
            import ipaddress
            
            # Convertir les préfixes en objets réseau
            network1 = ipaddress.ip_network(subnet1.get("prefix", "0.0.0.0/0"))
            network2 = ipaddress.ip_network(subnet2.get("prefix", "0.0.0.0/0"))
            
            # Vérifier le chevauchement
            return network1.overlaps(network2)
        except Exception:
            # En cas d'erreur, considérer qu'il n'y a pas de chevauchement
            return False 