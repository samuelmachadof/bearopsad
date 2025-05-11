from datetime import datetime, timedelta

class BloodhoundAnalyzer:
    def __init__(self, vuln_manager):
        """
        Analyseur des données Bloodhound
        
        Args:
            vuln_manager: Référence au gestionnaire de vulnérabilités principal
        """
        self.vuln_manager = vuln_manager
        
    def analyze(self, bloodhound_data):
        """
        Analyse complète des données Bloodhound
        
        Args:
            bloodhound_data: Dictionnaire contenant les données extraites de Bloodhound
        """
        if not bloodhound_data:
            return
        
        # Analyse des ACLs dangereuses
        if bloodhound_data.get("acls"):
            self._analyze_dangerous_acls(bloodhound_data.get("acls", {}))
            
        # Analyse des problèmes d'AdminCount=1
        if bloodhound_data.get("users"):
            self._analyze_admin_count(bloodhound_data.get("users", {}))
            
        # Analyse des délégations non contraintes (Unconstrained Delegation)
        if bloodhound_data.get("computers"):
            self._analyze_unconstrained_delegation(bloodhound_data.get("computers", {}))
            
        # Analyse des délégations basées sur les ressources (RBCD)
        if bloodhound_data.get("computers"):
            self._analyze_rbcd(bloodhound_data.get("computers", {}))
            
        # Analyse des droits DC Sync (GetChangesAll)
        if bloodhound_data.get("domains"):
            self._analyze_dcsync_rights(bloodhound_data.get("domains", {}))
            
        # Analyse des comptes avec SID History problématiques
        if bloodhound_data.get("users"):
            self._analyze_sid_history(bloodhound_data.get("users", {}))
            
        # Analyse des comptes obsolètes
        if bloodhound_data.get("users") and bloodhound_data.get("computers"):
            self._analyze_abandoned_accounts(
                bloodhound_data.get("users", {}),
                bloodhound_data.get("computers", {})
            )
            
        # Analyse des comptes sans MFA
        if bloodhound_data.get("users"):
            self._analyze_mfa_absent(bloodhound_data.get("users", {}))
            
        # Analyse des comptes avec PasswordNotRequired ou PasswordNeverExpires
        if bloodhound_data.get("users"):
            self._analyze_password_issues(bloodhound_data.get("users", {}))
            
        # Analyse des GPOs
        if bloodhound_data.get("gpos"):
            self._analyze_gpo_security(bloodhound_data.get("gpos", {}))
            
        # Analyse des OUs
        if bloodhound_data.get("ous"):
            self._analyze_ou_security(bloodhound_data.get("ous", {}))
            
        # Analyse des relations de confiance (trusts)
        if bloodhound_data.get("domains"):
            self._analyze_domain_trusts(bloodhound_data.get("domains", {}))
            
        # Analyse des utilisateurs kerberoastables
        if bloodhound_data.get("users"):
            self._analyze_kerberoastable_accounts(bloodhound_data.get("users", {}))
            
        # Analyse des groupes sensibles
        if bloodhound_data.get("groups"):
            self._analyze_sensitive_groups(bloodhound_data.get("groups", {}))
            
        # Analyse des utilisateurs protégés
        if bloodhound_data.get("users") and bloodhound_data.get("groups"):
            self._analyze_protected_users(
                bloodhound_data.get("users", {}),
                bloodhound_data.get("groups", {})
            )
            
        # Analyse des tentatives de mot de passe incorrectes
        if bloodhound_data.get("users"):
            self._analyze_bad_password_attempts(bloodhound_data.get("users", {}))
            
    def _analyze_dangerous_acls(self, acls):
        """Analyse les ACLs dangereuses dans les données Bloodhound"""
        dangerous_rights = ["GenericAll", "GenericWrite", "WriteOwner", "WriteDacl", "AddMember", "ForceChangePassword", "AllExtendedRights"]
        
        for object_id, acl_data in acls.items():
            for right, principals in acl_data.items():
                if right in dangerous_rights and principals:
                    for principal in principals:
                        principal_name = principal.get('name', 'Unknown Principal')
                        object_name = acl_data.get('name', 'Unknown Object')
                        object_type = acl_data.get('type', 'Unknown')
                        
                        self.vuln_manager.add_vulnerability(
                            title=f"Dangerous ACL: {right} on {object_type} '{object_name}' for '{principal_name}'",
                            asset_value=self.vuln_manager.target,
                            target=f"ldap://{self.vuln_manager.target}",
                            module="bloodhound",
                            type=1,  # NETWORK
                            protocol=0,  # TCP
                            port=389,  # LDAP
                            techno_value="Active Directory"
                        )
    
    def _analyze_admin_count(self, users):
        """Analyse les utilisateurs avec AdminCount=1"""
        for user_id, user_data in users.items():
            if user_data.get("adminCount") == 1:
                self.vuln_manager.add_vulnerability(
                    title=f"AdminCount=1 User: {user_data.get('name', 'Unknown User')}",
                    asset_value=self.vuln_manager.target,
                    target=f"ldap://{self.vuln_manager.target}",
                    module="bloodhound",
                    type=1,  # NETWORK
                    protocol=0,  # TCP
                    port=389,  # LDAP
                    techno_value="Active Directory"
                )
    
    def _analyze_unconstrained_delegation(self, computers):
        """Analyse les ordinateurs avec délégation non contrainte"""
        for computer_id, computer_data in computers.items():
            if computer_data.get("unConstrainedDelegation"):
                self.vuln_manager.add_vulnerability(
                    title=f"Unconstrained Delegation: {computer_data.get('name', 'Unknown Computer')}",
                    asset_value=self.vuln_manager.target,
                    target=f"ldap://{self.vuln_manager.target}",
                    module="bloodhound",
                    type=1,  # NETWORK
                    protocol=0,  # TCP
                    port=389,  # LDAP
                    techno_value="Active Directory"
                )
    
    def _analyze_rbcd(self, computers):
        """Analyse les ordinateurs avec RBCD configuré"""
        for computer_id, computer_data in computers.items():
            if computer_data.get("allowedToDelegate") and len(computer_data.get("allowedToDelegate", [])) > 0:
                delegations = ", ".join(computer_data.get("allowedToDelegate", []))
                self.vuln_manager.add_vulnerability(
                    title=f"RBCD Configured: {computer_data.get('name', 'Unknown Computer')} can delegate to {delegations}",
                    asset_value=self.vuln_manager.target,
                    target=f"ldap://{self.vuln_manager.target}",
                    module="bloodhound",
                    type=1,  # NETWORK
                    protocol=0,  # TCP
                    port=389,  # LDAP
                    techno_value="Active Directory"
                )
    
    def _analyze_dcsync_rights(self, domains):
        """Analyse les droits DCSync (GetChangesAll) dans le domaine"""
        for domain_id, domain_data in domains.items():
            if domain_data.get("objectid") and domain_data.get("acls"):
                acls = domain_data.get("acls", {})
                for right, principals in acls.items():
                    if right == "GetChangesAll" and principals:
                        for principal in principals:
                            self.vuln_manager.add_vulnerability(
                                title=f"DCSync Rights: {principal.get('name', 'Unknown Principal')} can perform DCSync on {domain_data.get('name', 'Unknown Domain')}",
                                asset_value=self.vuln_manager.target,
                                target=f"ldap://{self.vuln_manager.target}",
                                module="bloodhound",
                                type=1,  # NETWORK
                                protocol=0,  # TCP
                                port=389,  # LDAP
                                techno_value="Active Directory"
                            )
    
    def _analyze_sid_history(self, users):
        """Analyse les utilisateurs avec SID History problématique"""
        for user_id, user_data in users.items():
            if user_data.get("sidHistory") and len(user_data.get("sidHistory", [])) > 0:
                sid_count = len(user_data.get("sidHistory", []))
                self.vuln_manager.add_vulnerability(
                    title=f"SID History ({sid_count} entries): {user_data.get('name', 'Unknown User')}",
                    asset_value=self.vuln_manager.target,
                    target=f"ldap://{self.vuln_manager.target}",
                    module="bloodhound",
                    type=1,  # NETWORK
                    protocol=0,  # TCP
                    port=389,  # LDAP
                    techno_value="Active Directory"
                )
    
    def _analyze_abandoned_accounts(self, users, computers):
        """Analyse les comptes abandonnés (LastLogon ancien)"""
        # Analyse des utilisateurs abandonnés
        for user_id, user_data in users.items():
            if user_data.get("lastLogon") and self._is_date_old(user_data.get("lastLogon"), days=90):
                last_logon = user_data.get("lastLogon", "Unknown")
                self.vuln_manager.add_vulnerability(
                    title=f"Abandoned User Account: {user_data.get('name', 'Unknown User')} (Last Logon: {last_logon})",
                    asset_value=self.vuln_manager.target,
                    target=f"ldap://{self.vuln_manager.target}",
                    module="bloodhound",
                    type=1,  # NETWORK
                    protocol=0,  # TCP
                    port=389,  # LDAP
                    techno_value="Active Directory"
                )
        
        # Analyse des ordinateurs abandonnés
        for computer_id, computer_data in computers.items():
            if computer_data.get("lastLogon") and self._is_date_old(computer_data.get("lastLogon"), days=90):
                last_logon = computer_data.get("lastLogon", "Unknown")
                self.vuln_manager.add_vulnerability(
                    title=f"Abandoned Computer Account: {computer_data.get('name', 'Unknown Computer')} (Last Logon: {last_logon})",
                    asset_value=self.vuln_manager.target,
                    target=f"ldap://{self.vuln_manager.target}",
                    module="bloodhound",
                    type=1,  # NETWORK
                    protocol=0,  # TCP
                    port=389,  # LDAP
                    techno_value="Active Directory"
                )
    
    def _is_date_old(self, date_string, days=90):
        """Vérifie si une date est plus ancienne que le nombre de jours spécifié"""
        try:
            # Conversion de la chaîne de date en objet datetime
            # Format attendu : "2023-04-28T14:30:00Z"
            date_obj = datetime.fromisoformat(date_string.replace('Z', '+00:00'))
            threshold = datetime.now() - timedelta(days=days)
            return date_obj < threshold
        except Exception:
            return False
    
    def _analyze_mfa_absent(self, users):
        """Analyse les comptes sans MFA configuré"""
        sensitive_groups = ["Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Account Operators", "Server Operators"]
        
        for user_id, user_data in users.items():
            if user_data.get("memberOf"):
                user_groups = user_data.get("memberOf", [])
                is_admin = any(group in user_groups for group in sensitive_groups)
                
                if is_admin and not user_data.get("hasMFA", False):
                    # Liste des groupes critiques dont l'utilisateur est membre
                    critical_groups = [group for group in user_groups if group in sensitive_groups]
                    groups_str = ", ".join(critical_groups)
                    
                    self.vuln_manager.add_vulnerability(
                        title=f"Critical Account Without MFA: {user_data.get('name', 'Unknown User')} (Member of: {groups_str})",
                        asset_value=self.vuln_manager.target,
                        target=f"ldap://{self.vuln_manager.target}",
                        module="bloodhound",
                        type=1,  # NETWORK
                        protocol=0,  # TCP
                        port=389,  # LDAP
                        techno_value="Active Directory"
                    )
    
    def _analyze_password_issues(self, users):
        """Analyse les problèmes de mot de passe (PasswordNotRequired, PasswordNeverExpires)"""
        for user_id, user_data in users.items():
            # Vérification de PasswordNotRequired
            if user_data.get("userAccountControl", {}).get("PASSWD_NOTREQD"):
                self.vuln_manager.add_vulnerability(
                    title=f"PasswordNotRequired: {user_data.get('name', 'Unknown User')}",
                    asset_value=self.vuln_manager.target,
                    target=f"ldap://{self.vuln_manager.target}",
                    module="bloodhound",
                    type=1,  # NETWORK
                    protocol=0,  # TCP
                    port=389,  # LDAP
                    techno_value="Active Directory"
                )
            
            # Vérification de DONT_EXPIRE_PASSWORD
            if user_data.get("userAccountControl", {}).get("DONT_EXPIRE_PASSWORD"):
                self.vuln_manager.add_vulnerability(
                    title=f"PasswordNeverExpires: {user_data.get('name', 'Unknown User')}",
                    asset_value=self.vuln_manager.target,
                    target=f"ldap://{self.vuln_manager.target}",
                    module="bloodhound",
                    type=1,  # NETWORK
                    protocol=0,  # TCP
                    port=389,  # LDAP
                    techno_value="Active Directory"
                )
    
    def _analyze_gpo_security(self, gpos):
        """Analyse la sécurité des GPO"""
        for gpo_id, gpo_data in gpos.items():
            # Vérification des GPO avec des ACL dangereuses
            if gpo_data.get("acl") and self._has_dangerous_acl(gpo_data.get("acl", {})):
                self.vuln_manager.add_vulnerability(
                    title=f"GPO With Dangerous ACL: {gpo_data.get('name', 'Unknown GPO')}",
                    asset_value=self.vuln_manager.target,
                    target=f"ldap://{self.vuln_manager.target}",
                    module="bloodhound",
                    type=1,  # NETWORK
                    protocol=0,  # TCP
                    port=389,  # LDAP
                    techno_value="Active Directory"
                )
            
            # Vérification des GPO avec des paramètres de sécurité faibles
            if gpo_data.get("settings") and self._has_weak_settings(gpo_data.get("settings", {})):
                self.vuln_manager.add_vulnerability(
                    title=f"GPO With Weak Security Settings: {gpo_data.get('name', 'Unknown GPO')}",
                    asset_value=self.vuln_manager.target,
                    target=f"ldap://{self.vuln_manager.target}",
                    module="bloodhound",
                    type=1,  # NETWORK
                    protocol=0,  # TCP
                    port=389,  # LDAP
                    techno_value="Active Directory"
                )
                
            # Vérification des permissions abusables sur les GPO
            if gpo_data.get("permissions") and self._has_abusable_permissions(gpo_data.get("permissions", {})):
                self.vuln_manager.add_vulnerability(
                    title=f"GPO With Abusable Permissions: {gpo_data.get('name', 'Unknown GPO')}",
                    asset_value=self.vuln_manager.target,
                    target=f"ldap://{self.vuln_manager.target}",
                    module="bloodhound",
                    type=1,  # NETWORK
                    protocol=0,  # TCP
                    port=389,  # LDAP
                    techno_value="Active Directory"
                )
    
    def _has_dangerous_acl(self, acl):
        """Vérifie si une ACL contient des droits dangereux"""
        dangerous_rights = ["GenericAll", "GenericWrite", "WriteOwner", "WriteDacl", "AllExtendedRights"]
        for right in dangerous_rights:
            if right in acl and acl[right]:
                return True
        return False
    
    def _has_weak_settings(self, settings):
        """Vérifie si une GPO contient des paramètres de sécurité faibles"""
        # Vérification de paramètres de sécurité importants
        weak_settings = {
            "PasswordComplexity": False,
            "MinimumPasswordLength": lambda x: x < 8,
            "PasswordHistorySize": lambda x: x < 10,
            "LockoutThreshold": lambda x: x == 0,
            "RequireSmartCard": False,
            "NTLMv1Enabled": True,
            "SMBSigningRequired": False,
            "LDAPSigningRequired": False,
            "AnonymousAccessAllowed": True
        }
        
        for setting, check in weak_settings.items():
            if setting in settings:
                if callable(check):
                    if check(settings[setting]):
                        return True
                elif settings[setting] == check:
                    return True
        return False
    
    def _has_abusable_permissions(self, permissions):
        """Vérifie si les permissions sur une GPO sont abusables"""
        dangerous_permissions = ["CreateChild", "WriteProperty", "DeleteChild", "Delete", "WriteDacl", "WriteOwner"]
        for perm in permissions:
            if perm.get("permission") in dangerous_permissions:
                # Si la permission est attribuée à un groupe non administratif
                if perm.get("principal") and not self._is_admin_group(perm.get("principal")):
                    return True
        return False
    
    def _is_admin_group(self, group_name):
        """Vérifie si un groupe est un groupe d'administrateurs"""
        admin_groups = ["Domain Admins", "Enterprise Admins", "Administrators", "Schema Admins", "BUILTIN\\Administrators"]
        return group_name in admin_groups
    
    def _analyze_ou_security(self, ous):
        """Analyse la sécurité des OUs"""
        for ou_id, ou_data in ous.items():
            # Vérification des OUs avec des ACL dangereuses
            if ou_data.get("acl") and self._has_dangerous_acl(ou_data.get("acl", {})):
                self.vuln_manager.add_vulnerability(
                    title=f"OU With Dangerous ACL: {ou_data.get('name', 'Unknown OU')}",
                    asset_value=self.vuln_manager.target,
                    target=f"ldap://{self.vuln_manager.target}",
                    module="bloodhound",
                    type=1,  # NETWORK
                    protocol=0,  # TCP
                    port=389,  # LDAP
                    techno_value="Active Directory"
                )
                
    def _analyze_domain_trusts(self, domains):
        """Analyse les relations de confiance entre domaines"""
        for domain_id, domain_data in domains.items():
            if domain_data.get("trusts"):
                for trust in domain_data.get("trusts", []):
                    trust_type = trust.get("type", "Unknown")
                    trusted_domain = trust.get("targetDomain", "Unknown Domain")
                    is_transitive = trust.get("isTransitive", False)
                    is_external = trust_type == "External"
                    
                    if is_transitive or is_external:
                        self.vuln_manager.add_vulnerability(
                            title=f"Potentially Risky Domain Trust: {domain_data.get('name', 'Current Domain')} -> {trusted_domain} (Type: {trust_type}, Transitive: {is_transitive})",
                            asset_value=self.vuln_manager.target,
                            target=f"ldap://{self.vuln_manager.target}",
                            module="bloodhound",
                            type=1,  # NETWORK
                            protocol=0,  # TCP
                            port=389,  # LDAP
                            techno_value="Active Directory"
                        )
                        
    def _analyze_kerberoastable_accounts(self, users):
        """Analyse les comptes kerberoastables"""
        for user_id, user_data in users.items():
            if user_data.get("hasSPN") and not user_data.get("dontRequirePreauth", False):
                spns = user_data.get("servicePrincipalNames", [])
                spn_count = len(spns)
                
                # Considérer uniquement les comptes avec des SPNs actifs
                if spn_count > 0:
                    self.vuln_manager.add_vulnerability(
                        title=f"Kerberoastable Account: {user_data.get('name', 'Unknown User')} ({spn_count} SPNs)",
                        asset_value=self.vuln_manager.target,
                        target=f"ldap://{self.vuln_manager.target}",
                        module="bloodhound",
                        type=1,  # NETWORK
                        protocol=0,  # TCP
                        port=389,  # LDAP
                        techno_value="Active Directory"
                    )
                    
    def _analyze_sensitive_groups(self, groups):
        """Analyse les groupes sensibles"""
        sensitive_groups = {
            "Domain Admins": "Privileged group with full control over the domain",
            "Enterprise Admins": "Privileged group with full control over the forest",
            "Schema Admins": "Can modify the Active Directory schema",
            "Administrators": "Local administrators on the domain controller",
            "Account Operators": "Can create and modify user accounts",
            "Server Operators": "Can administer domain controllers",
            "Backup Operators": "Can backup and restore domain controller data",
            "Print Operators": "Can manage printers and potentially gain code execution",
            "DNSAdmins": "Can modify DNS settings and potentially gain code execution"
        }
        
        for group_id, group_data in groups.items():
            group_name = group_data.get("name", "")
            
            if group_name in sensitive_groups:
                members_count = len(group_data.get("members", []))
                description = sensitive_groups[group_name]
                
                self.vuln_manager.add_vulnerability(
                    title=f"Sensitive Group: {group_name} ({members_count} members) - {description}",
                    asset_value=self.vuln_manager.target,
                    target=f"ldap://{self.vuln_manager.target}",
                    module="bloodhound",
                    type=1,  # NETWORK
                    protocol=0,  # TCP
                    port=389,  # LDAP
                    techno_value="Active Directory"
                )
                
    def _analyze_protected_users(self, users, groups):
        """Analyse du groupe Protected Users"""
        # Recherche du groupe Protected Users
        protected_users_group = None
        for group_id, group_data in groups.items():
            if group_data.get("name") == "Protected Users":
                protected_users_group = group_data
                break
                
        if not protected_users_group:
            self.vuln_manager.add_vulnerability(
                title="Protected Users Group Not Found",
                asset_value=self.vuln_manager.target,
                target=f"ldap://{self.vuln_manager.target}",
                module="bloodhound",
                type=1,  # NETWORK
                protocol=0,  # TCP
                port=389,  # LDAP
                techno_value="Active Directory"
            )
            return
            
        # Vérification des administrateurs qui ne sont pas dans Protected Users
        admin_groups = ["Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators"]
        protected_members = protected_users_group.get("members", [])
        
        for user_id, user_data in users.items():
            user_groups = user_data.get("memberOf", [])
            is_admin = any(group in user_groups for group in admin_groups)
            is_protected = user_id in protected_members
            
            if is_admin and not is_protected:
                admin_roles = [group for group in user_groups if group in admin_groups]
                roles_str = ", ".join(admin_roles)
                
                self.vuln_manager.add_vulnerability(
                    title=f"Administrative User Not Protected: {user_data.get('name', 'Unknown User')} (Roles: {roles_str})",
                    asset_value=self.vuln_manager.target,
                    target=f"ldap://{self.vuln_manager.target}",
                    module="bloodhound",
                    type=1,  # NETWORK
                    protocol=0,  # TCP
                    port=389,  # LDAP
                    techno_value="Active Directory"
                )
                
    def _analyze_bad_password_attempts(self, users):
        """Analyse les tentatives de mauvais mots de passe"""
        threshold = 10  # Seuil à partir duquel on considère qu'il y a un problème
        
        for user_id, user_data in users.items():
            if user_data.get("badPwdCount", 0) >= threshold:
                bad_count = user_data.get("badPwdCount", 0)
                
                self.vuln_manager.add_vulnerability(
                    title=f"High Bad Password Count: {user_data.get('name', 'Unknown User')} ({bad_count} attempts)",
                    asset_value=self.vuln_manager.target,
                    target=f"ldap://{self.vuln_manager.target}",
                    module="bloodhound",
                    type=1,  # NETWORK
                    protocol=0,  # TCP
                    port=389,  # LDAP
                    techno_value="Active Directory"
                ) 