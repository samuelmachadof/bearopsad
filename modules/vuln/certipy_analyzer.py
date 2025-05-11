class CertipyAnalyzer:
    def __init__(self, vuln_manager):
        """
        Analyseur des données de Certipy (Shadow Credentials et ESC)
        
        Args:
            vuln_manager: Référence au gestionnaire de vulnérabilités principal
        """
        self.vuln_manager = vuln_manager
        
    def analyze_shadow_credentials(self, results):
        """
        Analyse les résultats de la détection de Shadow Credentials
        
        Args:
            results: Dictionnaire contenant les résultats de la recherche de Shadow Credentials
        """
        if not results or not results.get("vulnerable_targets"):
            return
            
        for target in results.get("vulnerable_targets", []):
            target_name = target.get("name", "Unknown Target")
            target_type = target.get("type", "Unknown")
            msds_key_count = len(target.get("msds_keycredentiallink", []))
            
            if target.get("exploited"):
                severity_note = " (Successfully Exploited)"
            else:
                severity_note = f" ({msds_key_count} Key Credentials)"
            
            self.vuln_manager.add_vulnerability(
                title=f"Shadow Credentials Vulnerability: {target_type} '{target_name}'{severity_note}",
                asset_value=self.vuln_manager.target,
                target=f"ldap://{self.vuln_manager.target}",
                module="certipy",
                type=1,  # NETWORK
                protocol=0,  # TCP
                port=389,  # LDAP
                techno_value="Active Directory"
            )
            
            # Si on a récupéré des hashes, on les enregistre comme vulnérabilité distincte
            if target.get("hashes"):
                self.vuln_manager.add_vulnerability(
                    title=f"Shadow Credentials Stolen Credentials: {target_name}",
                    asset_value=self.vuln_manager.target,
                    target=f"ldap://{self.vuln_manager.target}",
                    module="certipy",
                    type=1,  # NETWORK
                    protocol=0,  # TCP
                    port=389,  # LDAP
                    techno_value="Active Directory"
                )
            
    def analyze_certificates(self, results):
        """
        Analyse les résultats de la détection de templates de certificats vulnérables
        
        Args:
            results: Dictionnaire contenant les résultats de l'analyse des certificats
        """
        if not results:
            return
            
        if results.get("templates"):
            self._analyze_certificate_templates(results.get("templates", []))
        
        if results.get("certificate_authorities"):
            self._analyze_certificate_authorities(results.get("certificate_authorities", []))
            
        # Si disponible, analyser l'AD CS complet
        if results.get("adcs_configuration"):
            self._analyze_adcs_configuration(results.get("adcs_configuration", {}))
            
    def _analyze_certificate_templates(self, templates):
        """
        Analyse les templates de certificats pour détecter les vulnérabilités ESC
        
        Args:
            templates: Liste des templates de certificats
        """
        esc_vulnerabilities = {
            "ESC1": "Client Authentication + enrollee supplies subject",
            "ESC2": "Any Purpose EKU or no EKU restrictions",
            "ESC3": "Enrollment rights for Domain Computers/Controllers",
            "ESC4": "EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled on CA",
            "ESC5": "Vulnerable Certificate Authority access control",
            "ESC6": "EDITF_ATTRIBUTESUBJECTALTNAME2 + Write permissions",
            "ESC7": "Vulnerable Certificate Authority enrollment service",
            "ESC8": "HTTP/HTTPS Certificate Template",
            "ESC9": "Certificate template to domain controller authentication",
            "ESC10": "Template specifies subordinate CA certificate",
            "ESC11": "Vulnerable Certificate Authority (external) enrollment service"
        }
        
        for template in templates:
            template_name = template.get("name", "Unknown Template")
            template_display_name = template.get("display_name", template_name)
            
            # Vérifier toutes les ESC possibles
            for esc_num in range(1, 12):
                esc_key = f"vulnerable_esc{esc_num}"
                if template.get(esc_key, False):
                    esc_name = f"ESC{esc_num}"
                    esc_description = esc_vulnerabilities.get(esc_name, "Misconfigured certificate template")
                    
                    self.vuln_manager.add_vulnerability(
                        title=f"{esc_name} - {esc_description}: {template_display_name}",
                        asset_value=self.vuln_manager.target,
                        target=f"ldap://{self.vuln_manager.target}",
                        module="certipy",
                        type=3,  # CERTIFICATE
                        protocol=0,  # TCP
                        port=389,  # LDAP
                        techno_value="AD CS"
                    )
            
            # Vérifier aussi par méthode manuelle si le flag n'est pas encore défini
            if not any(template.get(f"vulnerable_esc{i}", False) for i in range(1, 12)):
                for esc_func in [
                    self._is_vulnerable_to_esc1,
                    self._is_vulnerable_to_esc2,
                    self._is_vulnerable_to_esc3,
                    self._is_vulnerable_to_esc8
                ]:
                    if esc_func(template):
                        func_name = esc_func.__name__
                        esc_num = func_name.split("_")[-1]  # Extrait le numéro ESC du nom de la fonction
                        esc_description = esc_vulnerabilities.get(esc_num.upper(), "Misconfigured certificate template")
                        
                        self.vuln_manager.add_vulnerability(
                            title=f"{esc_num.upper()} - {esc_description}: {template_display_name}",
                            asset_value=self.vuln_manager.target,
                            target=f"ldap://{self.vuln_manager.target}",
                            module="certipy",
                            type=3,  # CERTIFICATE
                            protocol=0,  # TCP
                            port=389,  # LDAP
                            techno_value="AD CS"
                        )
                
    def _analyze_certificate_authorities(self, cas):
        """
        Analyse les autorités de certification pour détecter les vulnérabilités
        
        Args:
            cas: Liste des autorités de certification
        """
        for ca in cas:
            ca_name = ca.get("name", "Unknown CA")
            
            # Détection de configurations faibles de CA
            if self._has_weak_ca_configuration(ca):
                weak_configs = self._get_weak_ca_configurations(ca)
                config_summary = ", ".join(weak_configs)
                
                self.vuln_manager.add_vulnerability(
                    title=f"Weak CA Configuration: {ca_name} ({config_summary})",
                    asset_value=self.vuln_manager.target,
                    target=f"ldap://{self.vuln_manager.target}",
                    module="certipy",
                    type=3,  # CERTIFICATE
                    protocol=0,  # TCP
                    port=389,  # LDAP
                    techno_value="AD CS"
                )
                
            # Détection ESC4 (EDITF_ATTRIBUTESUBJECTALTNAME2 flag)
            if self._is_vulnerable_to_esc4(ca):
                self.vuln_manager.add_vulnerability(
                    title=f"ESC4 - EDITF_ATTRIBUTESUBJECTALTNAME2 Flag Enabled: {ca_name}",
                    asset_value=self.vuln_manager.target,
                    target=f"ldap://{self.vuln_manager.target}",
                    module="certipy",
                    type=3,  # CERTIFICATE
                    protocol=0,  # TCP
                    port=389,  # LDAP
                    techno_value="AD CS"
                )
                
            # Vérification de la présence du service d'inscription CA
            if ca.get("web_enrollment_enabled", False):
                self.vuln_manager.add_vulnerability(
                    title=f"CA Web Enrollment Service Enabled: {ca_name}",
                    asset_value=self.vuln_manager.target,
                    target=f"http://{self.vuln_manager.target}/certsrv/",
                    module="certipy",
                    type=3,  # CERTIFICATE
                    protocol=0,  # TCP
                    port=80,  # HTTP
                    techno_value="AD CS"
                )
                
    def _analyze_adcs_configuration(self, adcs_config):
        """
        Analyse la configuration globale d'AD CS
        
        Args:
            adcs_config: Configuration globale AD CS
        """
        # Vérifier si AD CS est installé mais mal configuré
        if adcs_config.get("installed") and adcs_config.get("misconfigured", False):
            self.vuln_manager.add_vulnerability(
                title="AD CS Misconfiguration Detected",
                asset_value=self.vuln_manager.target,
                target=f"ldap://{self.vuln_manager.target}",
                module="certipy",
                type=3,  # CERTIFICATE
                protocol=0,  # TCP
                port=389,  # LDAP
                techno_value="AD CS"
            )
            
        # Vérifier la chaîne de certification
        if adcs_config.get("certificate_chain_issues", False):
            self.vuln_manager.add_vulnerability(
                title="AD CS Certificate Chain Issues Detected",
                asset_value=self.vuln_manager.target,
                target=f"ldap://{self.vuln_manager.target}",
                module="certipy",
                type=3,  # CERTIFICATE
                protocol=0,  # TCP
                port=389,  # LDAP
                techno_value="AD CS"
            )
            
        # Vérifier les services d'inscription
        for service in adcs_config.get("enrollment_services", []):
            service_name = service.get("name", "Unknown Service")
            if service.get("vulnerable", False):
                vuln_type = service.get("vulnerability_type", "Unknown Vulnerability")
                self.vuln_manager.add_vulnerability(
                    title=f"Vulnerable Enrollment Service: {service_name} ({vuln_type})",
                    asset_value=self.vuln_manager.target,
                    target=f"ldap://{self.vuln_manager.target}",
                    module="certipy",
                    type=3,  # CERTIFICATE
                    protocol=0,  # TCP
                    port=389,  # LDAP
                    techno_value="AD CS"
                )
                
    def _is_vulnerable_to_esc1(self, template):
        """
        Vérifie si un template est vulnérable à ESC1
        
        Conditions:
        - Client Authentication EKU
        - CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag
        - Low enrollment permissions
        """
        if template.get("vulnerable_esc1", False):
            return True
            
        ekus = template.get("ekus", [])
        flags = template.get("flags", {})
        
        return (
            "Client Authentication" in ekus and
            flags.get("CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT", False) and
            self._has_weak_enrollment_permissions(template)
        )
        
    def _is_vulnerable_to_esc2(self, template):
        """
        Vérifie si un template est vulnérable à ESC2
        
        Conditions:
        - Any Purpose EKU or no EKU restrictions
        - Low enrollment permissions
        """
        if template.get("vulnerable_esc2", False):
            return True
            
        ekus = template.get("ekus", [])
        
        return (
            (not ekus or "Any Purpose" in ekus) and
            self._has_weak_enrollment_permissions(template)
        )
        
    def _is_vulnerable_to_esc3(self, template):
        """
        Vérifie si un template est vulnérable à ESC3
        
        Conditions:
        - Enrollment rights for Domain Computers or Domain Controllers
        - Client Authentication EKU
        """
        if template.get("vulnerable_esc3", False):
            return True
            
        enrollment_permissions = template.get("enrollment_permissions", [])
        ekus = template.get("ekus", [])
        
        has_computer_enrollment = any(
            perm.get("name") in ["Domain Computers", "Domain Controllers"] 
            for perm in enrollment_permissions
        )
        
        return has_computer_enrollment and "Client Authentication" in ekus
        
    def _is_vulnerable_to_esc8(self, template):
        """
        Vérifie si un template est vulnérable à ESC8
        
        Conditions:
        - HTTP/HTTPS Authentication EKU
        """
        if template.get("vulnerable_esc8", False):
            return True
            
        ekus = template.get("ekus", [])
        
        return any(eku in ["HTTP Authentication", "HTTPS Authentication"] for eku in ekus)
        
    def _is_vulnerable_to_esc4(self, ca):
        """
        Vérifie si une CA est vulnérable à ESC4
        
        Conditions:
        - EDITF_ATTRIBUTESUBJECTALTNAME2 flag
        """
        if ca.get("vulnerable_esc4", False):
            return True
            
        flags = ca.get("flags", {})
        
        return flags.get("EDITF_ATTRIBUTESUBJECTALTNAME2", False)
        
    def _has_weak_enrollment_permissions(self, template):
        """
        Vérifie si un template a des permissions d'enrôlement faibles
        """
        enrollment_permissions = template.get("enrollment_permissions", [])
        
        # Considéré faible si "Authenticated Users" ou "Domain Users" peuvent s'enrôler
        return any(
            perm.get("name") in ["Authenticated Users", "Domain Users", "Everyone"] 
            for perm in enrollment_permissions
        )
        
    def _has_weak_ca_configuration(self, ca):
        """
        Vérifie si une CA a une configuration faible
        """
        flags = ca.get("flags", {})
        
        # Vérifier les flags de sécurité importants
        return not (
            flags.get("ENFORCE_ENCRYPTION", False) and 
            flags.get("ENFORCE_SIGNING", False) and 
            not flags.get("ALLOW_REQUEST_SYMMETRICALGOPRIVATE", False)
        ) or flags.get("EDITF_ATTRIBUTESUBJECTALTNAME2", False)
    
    def _get_weak_ca_configurations(self, ca):
        """
        Retourne une liste des configurations faibles détectées pour une CA
        """
        weak_configs = []
        flags = ca.get("flags", {})
        
        if not flags.get("ENFORCE_ENCRYPTION", False):
            weak_configs.append("No Encryption Enforcement")
            
        if not flags.get("ENFORCE_SIGNING", False):
            weak_configs.append("No Signing Enforcement")
            
        if flags.get("ALLOW_REQUEST_SYMMETRICALGOPRIVATE", False):
            weak_configs.append("Symmetric Key Algorithm Allowed")
            
        if flags.get("EDITF_ATTRIBUTESUBJECTALTNAME2", False):
            weak_configs.append("Subject Alternative Name Allowed")
            
        return weak_configs 