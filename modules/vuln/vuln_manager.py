import json
from datetime import datetime
import os
import importlib
from ..vuln_constants import SERVICE_TYPE, PROTOCOL_TYPE, PORTS, VULN_CATEGORIES, SEVERITY, DETECTION_RULES

# Import des différents modules d'analyse
from .bloodhound_analyzer import BloodhoundAnalyzer
from .certipy_analyzer import CertipyAnalyzer
from .smb_analyzer import SMBAnalyzer
from .ldap_analyzer import LDAPAnalyzer
from .dns_analyzer import DNSAnalyzer
from .kerberos_analyzer import KerberosAnalyzer
from .infrastructure_analyzer import InfrastructureAnalyzer
from .sites_analyzer import SitesAnalyzer

class VulnManager:
    def __init__(self):
        self.vulnerabilities = []
        self.output_dir = None
        self.raw_logs_dir = None
        self.parsed_dir = None
        self.target = None
        self.domain = None
        
        # Initialisation des analyseurs spécifiques
        self.bloodhound_analyzer = BloodhoundAnalyzer(self)
        self.certipy_analyzer = CertipyAnalyzer(self)
        self.smb_analyzer = SMBAnalyzer(self)
        self.ldap_analyzer = LDAPAnalyzer(self)
        self.dns_analyzer = DNSAnalyzer(self)
        self.kerberos_analyzer = KerberosAnalyzer(self)
        self.infrastructure_analyzer = InfrastructureAnalyzer(self)
        self.sites_analyzer = SitesAnalyzer(self)
        
    def set_output_dir(self, output_dir, raw_logs_dir, parsed_dir):
        """Configure les répertoires de sortie"""
        self.output_dir = output_dir
        self.raw_logs_dir = raw_logs_dir
        self.parsed_dir = parsed_dir
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(raw_logs_dir, exist_ok=True)
        os.makedirs(parsed_dir, exist_ok=True)
        
    def set_target(self, target, domain=None):
        """Configure la cible et le domaine"""
        self.target = target
        self.domain = domain

    def add_vulnerability(self, title, asset_value, target, module, type, protocol, 
                        port=None, techno_value=None, version=None):
        """Ajoute une vulnérabilité avec le format standardisé"""
        vuln = {
            "title": title,
            "assetValue": asset_value,
            "target": target,
            "module": module,
            "type": type,
            "protocol": protocol,
            "port": port,
            "technoValue": techno_value
        }
        
        # Ajout conditionnel de la version si elle est fournie
        if version:
            vuln["version"] = version
            
        self.vulnerabilities.append(vuln)
        return vuln

    # Méthodes d'analyse déléguées aux analyseurs spécifiques
    def analyze_smb_security(self, results):
        """Analyse approfondie de la sécurité SMB"""
        self.smb_analyzer.analyze(results)

    def analyze_kerberos_security(self, results):
        """Analyse approfondie de la sécurité Kerberos"""
        self.kerberos_analyzer.analyze(results)

    def analyze_ldap_security(self, results):
        """Analyse approfondie de la sécurité LDAP"""
        self.ldap_analyzer.analyze(results)

    def analyze_certificate_security(self, results):
        """Analyse approfondie de la sécurité des certificats"""
        self.certipy_analyzer.analyze_certificates(results)

    def analyze_infrastructure(self, results):
        """Analyse approfondie de l'infrastructure"""
        self.infrastructure_analyzer.analyze(results)

    def analyze_bloodhound_data(self, bloodhound_data):
        """Analyse les données collectées par Bloodhound pour détecter les vulnérabilités avancées"""
        self.bloodhound_analyzer.analyze(bloodhound_data)
    
    def analyze_shadow_credentials(self, results):
        """Analyse les résultats de recherche de Shadow Credentials"""
        self.certipy_analyzer.analyze_shadow_credentials(results)
    
    def analyze_dns_security(self, results):
        """Analyse la sécurité DNS"""
        self.dns_analyzer.analyze(results)
        
    def analyze_sites_and_services(self, results):
        """Analyse les sites et services AD"""
        self.sites_analyzer.analyze(results)

    def save_vulnerabilities(self):
        """Sauvegarde les vulnérabilités dans un fichier JSON"""
        if not self.vulnerabilities:
            return None
            
        timestamp = datetime.now().strftime("%H%M%S")
        vuln_file = os.path.join(self.parsed_dir, f"vulnerabilities_{timestamp}.json")
        
        # Ajout des statistiques
        stats = {
            "total": len(self.vulnerabilities),
            "by_type": {},
            "by_severity": {}
        }
        
        for vuln in self.vulnerabilities:
            vuln_type = vuln.get("type", "unknown")
            severity = vuln.get("severity", "unknown")
            
            stats["by_type"][vuln_type] = stats["by_type"].get(vuln_type, 0) + 1
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1
        
        output = {
            "timestamp": datetime.now().isoformat(),
            "target": self.target,
            "domain": self.domain,
            "stats": stats,
            "vulnerabilities": self.vulnerabilities
        }
        
        with open(vuln_file, 'w') as f:
            json.dump(output, f, indent=4)
            
        print(f"[+] Vulnérabilités sauvegardées dans {vuln_file}")
        return vuln_file

    def get_vulnerabilities(self):
        """Retourne la liste des vulnérabilités"""
        return self.vulnerabilities 