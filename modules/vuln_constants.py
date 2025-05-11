# Types de services
SERVICE_TYPE = {
    "DNS": 0,
    "NETWORK": 1,
    "WEB": 2,
    "CERTIFICATE": 3
}

# Types de protocoles
PROTOCOL_TYPE = {
    "TCP": 0,
    "UDP": 1,
    "ICMP": 2
}

# Ports standards
PORTS = {
    "DNS": 53,
    "KERBEROS": 88,
    "LDAP": 389,
    "LDAPS": 636,
    "SMB": 445,
    "RPC": 135,
    "WinRM": 5985,
    "WinRMS": 5986
}

# Catégories de vulnérabilités AD
VULN_CATEGORIES = {
    "AUTHENTICATION": {
        "description": "Vulnérabilités liées à l'authentification",
        "subcategories": [
            "KERBEROS_CONFIGURATION",
            "PASSWORD_POLICY",
            "NTLM_SECURITY",
            "MFA",
            "SHADOW_CREDENTIALS"
        ]
    },
    "ACCESS_CONTROL": {
        "description": "Vulnérabilités liées aux contrôles d'accès",
        "subcategories": [
            "ACL_MISCONFIGURATION",
            "PRIVILEGED_ACCOUNTS",
            "GROUP_POLICY",
            "DELEGATION",
            "RBCD",
            "DCSYNC",
            "ADMIN_COUNT"
        ]
    },
    "PROTOCOL_SECURITY": {
        "description": "Vulnérabilités liées aux protocoles",
        "subcategories": [
            "SMB_SECURITY",
            "LDAP_SECURITY",
            "DNS_SECURITY",
            "RPC_SECURITY"
        ]
    },
    "CERTIFICATE_SERVICES": {
        "description": "Vulnérabilités liées aux services de certificats",
        "subcategories": [
            "TEMPLATE_MISCONFIGURATION",
            "ENROLLMENT_RIGHTS",
            "CA_CONFIGURATION"
        ]
    },
    "INFRASTRUCTURE": {
        "description": "Vulnérabilités liées à l'infrastructure",
        "subcategories": [
            "OS_VERSION",
            "PATCH_MANAGEMENT",
            "BACKUP_SECURITY",
            "MONITORING",
            "ABANDONED_ACCOUNTS",
            "PASSWORD_SETTINGS"
        ]
    }
}

# Niveaux de sévérité
SEVERITY = {
    "CRITICAL": {
        "value": 4,
        "description": "Vulnérabilité critique nécessitant une action immédiate"
    },
    "HIGH": {
        "value": 3,
        "description": "Vulnérabilité importante à corriger rapidement"
    },
    "MEDIUM": {
        "value": 2,
        "description": "Vulnérabilité à corriger dans un délai raisonnable"
    },
    "LOW": {
        "value": 1,
        "description": "Vulnérabilité mineure à surveiller"
    },
    "INFO": {
        "value": 0,
        "description": "Information de sécurité"
    }
}

# Règles de détection basées sur PingCastle, ADCheck et ORADAD
DETECTION_RULES = {
    "KERBEROS": {
        "AS_REP_ROASTING": {
            "title": "AS-REP Roasting Possible",
            "description": "Utilisateurs avec Kerberos pre-authentication désactivée",
            "severity": "HIGH",
            "category": "AUTHENTICATION",
            "remediation": "Activer la pré-authentification Kerberos pour tous les comptes"
        },
        "KERBEROASTING": {
            "title": "Kerberoasting Possible",
            "description": "Comptes de service avec SPN vulnérables au Kerberoasting",
            "severity": "HIGH",
            "category": "AUTHENTICATION",
            "remediation": "Utiliser des mots de passe complexes pour les comptes de service"
        }
    },
    "SMB": {
        "SIGNING_DISABLED": {
            "title": "SMB Signing Not Required",
            "description": "La signature SMB n'est pas obligatoire",
            "severity": "HIGH",
            "category": "PROTOCOL_SECURITY",
            "remediation": "Activer la signature SMB obligatoire via GPO"
        },
        "GUEST_ACCESS": {
            "title": "Guest Access Allowed",
            "description": "Accès anonyme/guest autorisé",
            "severity": "HIGH",
            "category": "ACCESS_CONTROL",
            "remediation": "Désactiver le compte guest et les accès anonymes"
        }
    },
    "LDAP": {
        "ANONYMOUS_BIND": {
            "title": "LDAP Anonymous Bind Allowed",
            "description": "Liaison LDAP anonyme autorisée",
            "severity": "HIGH",
            "category": "PROTOCOL_SECURITY",
            "remediation": "Désactiver les liaisons LDAP anonymes"
        },
        "CLEARTEXT_AUTH": {
            "title": "LDAP Cleartext Authentication",
            "description": "Authentification LDAP en clair autorisée",
            "severity": "HIGH",
            "category": "PROTOCOL_SECURITY",
            "remediation": "Forcer LDAPS ou la signature LDAP"
        }
    },
    "CERTIFICATE": {
        "ESC1": {
            "title": "ESC1 - Misconfigured Certificate Templates",
            "description": "Templates de certificats mal configurés permettant l'escalade de privilèges",
            "severity": "CRITICAL",
            "category": "CERTIFICATE_SERVICES",
            "remediation": "Revoir et corriger les permissions des templates"
        },
        "ESC8": {
            "title": "ESC8 - HTTP/HTTPS Certificate Templates",
            "description": "Templates autorisant l'authentification HTTP/HTTPS",
            "severity": "HIGH",
            "category": "CERTIFICATE_SERVICES",
            "remediation": "Désactiver ou sécuriser les templates HTTP/HTTPS"
        },
        "SHADOW_CREDENTIALS": {
            "title": "Shadow Credentials Vulnerability",
            "description": "Vulnérabilité aux attaques Shadow Credentials via msDS-KeyCredentialLink",
            "severity": "HIGH",
            "category": "AUTHENTICATION",
            "remediation": "Revoir et corriger les ACLs sur l'attribut msDS-KeyCredentialLink"
        }
    },
    "INFRASTRUCTURE": {
        "OUTDATED_OS": {
            "title": "Outdated Operating System",
            "description": "Système d'exploitation obsolète ou non supporté",
            "severity": "HIGH",
            "category": "INFRASTRUCTURE",
            "remediation": "Mettre à jour vers une version supportée"
        },
        "WEAK_PASSWORD_POLICY": {
            "title": "Weak Password Policy",
            "description": "Politique de mot de passe insuffisante",
            "severity": "HIGH",
            "category": "AUTHENTICATION",
            "remediation": "Renforcer la politique de mots de passe via GPO"
        },
        "PASSWORD_NOT_REQUIRED": {
            "title": "Password Not Required",
            "description": "Comptes utilisateurs sans obligation de mot de passe",
            "severity": "CRITICAL",
            "category": "AUTHENTICATION",
            "remediation": "Désactiver l'option 'PasswordNotRequired' pour tous les comptes"
        },
        "PASSWORD_NEVER_EXPIRES": {
            "title": "Password Never Expires",
            "description": "Comptes utilisateurs dont le mot de passe n'expire jamais",
            "severity": "HIGH",
            "category": "AUTHENTICATION",
            "remediation": "Configurer l'expiration des mots de passe pour tous les comptes"
        },
        "ABANDONED_ACCOUNTS": {
            "title": "Abandoned Accounts",
            "description": "Comptes utilisateurs ou ordinateurs inactifs depuis longtemps",
            "severity": "MEDIUM",
            "category": "INFRASTRUCTURE",
            "remediation": "Désactiver ou supprimer les comptes inactifs"
        }
    },
    "DELEGATION": {
        "UNCONSTRAINED": {
            "title": "Unconstrained Delegation",
            "description": "Délégation non contrainte configurée",
            "severity": "HIGH",
            "category": "ACCESS_CONTROL",
            "remediation": "Utiliser la délégation contrainte ou basée sur les ressources"
        },
        "RBCD": {
            "title": "Resource-Based Constrained Delegation",
            "description": "Délégation basée sur les ressources mal configurée",
            "severity": "HIGH",
            "category": "ACCESS_CONTROL",
            "remediation": "Vérifier et corriger les configurations RBCD"
        }
    },
    "PRIVILEGED_ACCESS": {
        "DCSYNC_RIGHTS": {
            "title": "DCSync Rights",
            "description": "Droits permettant l'exécution de DCSync pour extraire les hachages",
            "severity": "CRITICAL",
            "category": "ACCESS_CONTROL",
            "remediation": "Retirer les droits GetChangesAll du domaine"
        },
        "ADMIN_COUNT": {
            "title": "AdminCount=1",
            "description": "Comptes avec AdminCount=1 mais n'appartenant plus à des groupes protégés",
            "severity": "MEDIUM",
            "category": "ACCESS_CONTROL",
            "remediation": "Nettoyer l'attribut AdminCount des comptes non-administrateurs"
        },
        "NO_MFA": {
            "title": "Critical Account Without MFA",
            "description": "Comptes privilégiés sans authentification multi-facteurs",
            "severity": "HIGH",
            "category": "AUTHENTICATION",
            "remediation": "Configurer MFA pour tous les comptes privilégiés"
        },
        "SID_HISTORY": {
            "title": "SID History Misconfiguration",
            "description": "Comptes avec SID History pouvant être utilisé pour l'escalade de privilèges",
            "severity": "HIGH",
            "category": "ACCESS_CONTROL",
            "remediation": "Nettoyer l'attribut SID History des comptes sensibles"
        }
    },
    "DNS": {
        "ZONE_TRANSFER": {
            "title": "DNS Zone Transfer Allowed",
            "description": "Transfert de zone DNS autorisé",
            "severity": "MEDIUM",
            "category": "PROTOCOL_SECURITY",
            "remediation": "Restreindre les transferts de zone aux serveurs autorisés uniquement"
        },
        "SENSITIVE_RECORDS": {
            "title": "Sensitive DNS Records Exposed",
            "description": "Enregistrements DNS sensibles exposés",
            "severity": "MEDIUM",
            "category": "PROTOCOL_SECURITY",
            "remediation": "Revoir et corriger les enregistrements DNS sensibles"
        }
    },
    "GROUP_POLICY": {
        "DANGEROUS_ACL": {
            "title": "GPO With Dangerous ACL",
            "description": "GPO avec des ACL dangereuses pouvant permettre des modifications non autorisées",
            "severity": "HIGH",
            "category": "ACCESS_CONTROL",
            "remediation": "Revoir et corriger les ACL des GPO"
        },
        "WEAK_SETTINGS": {
            "title": "GPO With Weak Security Settings",
            "description": "GPO avec des paramètres de sécurité faibles",
            "severity": "MEDIUM",
            "category": "INFRASTRUCTURE",
            "remediation": "Renforcer les paramètres de sécurité des GPO"
        }
    },
    "ACTIVE_DIRECTORY": {
        "SITE_MISCONFIGURATION": {
            "title": "Misconfigured AD Site",
            "description": "Site Active Directory mal configuré",
            "severity": "LOW",
            "category": "INFRASTRUCTURE",
            "remediation": "Revoir et corriger la configuration des sites AD"
        },
        "DANGEROUS_ACL": {
            "title": "Dangerous ACL",
            "description": "ACL dangereuses sur des objets sensibles",
            "severity": "HIGH",
            "category": "ACCESS_CONTROL",
            "remediation": "Revoir et corriger les ACL sur les objets sensibles"
        }
    }
} 