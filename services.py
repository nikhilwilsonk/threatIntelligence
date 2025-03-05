from urllib.parse import urlparse
import requests
import logging
from typing import List, Dict
import base64

from config import Config
from Models.ThreatIntelligenceModel import ThreatIntelligence

class OSINTCollector:
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

    def analyze_url(self, url: str) -> Dict:
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc

            vt_result = self.virustotal_url_analysis(url)
            shodan_result = self.shodan_host_analysis(domain)
            combined_result = {
                'url': url,
                'domain': domain,
                'virustotal': vt_result,
                'shodan': shodan_result,
                'overall_risk_score': self.calculate_risk_score(vt_result, shodan_result)
            }
            self.save_url_threat(combined_result)
            return combined_result
        
        except Exception as e:
            self.logger.error(f"URL Analysis Error: {e}")
            return {'error': str(e)}

    def collect_virustotal_threats(self,url:str) -> List[Dict]:
        try:
            url_encode=base64.urlsafe_b64encode(url.encode()).decode().strip('=')
            headers = {
                'x-apikey': Config.VIRUSTOTAL_API_KEY
            }
            url_id = requests.get(
                f'https://www.virustotal.com/api/v3/urls/{url_encode}',
                headers=headers
            ).json()
            analysis_response = requests.get(
                f'https://www.virustotal.com/api/v3/analyses/{url_id["data"]["id"]}',
                headers=headers
            ).json()
            return {
                'malicious_count': analysis_response.get('malicious', 0),
                'suspicious_count': analysis_response.get('suspicious', 0),
                'harmless_count': analysis_response.get('harmless', 0),
                'undetected_count': analysis_response.get('undetected', 0)
            }
        
        except Exception as e:
            self.logger.error(f"VirusTotal Analysis Error: {e}")
            return {'error': str(e)}
    
    def shodan_host_analysis(self,domain: str) -> List[Dict]:
        try:
            host_info_response = requests.get(
                f'https://api.shodan.io/dns/resolve',
                params={
                    'key': Config.SHODAN_API_KEY,
                    'hostnames': domain
                }
            )
            if host_info_response.status_code == 200:
                ip = list(host_info_response.json().values())[0]
                host_details_response = requests.get(
                    f'https://api.shodan.io/shodan/host/{ip}',
                    params={'key': Config.SHODAN_API_KEY}
                )
                if host_details_response.status_code == 200:
                    host_data = host_details_response.json()
                    return {
                        'ip': ip,
                        'total_ports_open': len(host_data.get('ports', [])),
                        'vulnerable_services': [
                            service for service in host_data.get('data', []) 
                            if 'vulners' in str(service).lower()
                        ],
                        'country': host_data.get('country_name', 'Unknown'),
                        'organization': host_data.get('org', 'Unknown'),
                        'last_update': host_data.get('last_update', 'Unknown')
                    }
            
            return {
                'error': 'Unable to resolve host or retrieve Shodan information'
            }
        
        except Exception as e:
            self.logger.error(f"Shodan Analysis Error: {e}")
            return {'error': str(e)}
    
    def calculate_risk_score(self,vt_result: Dict, shodan_result: Dict) -> float:
        try:
            vt_risk = (
                (vt_result.get('malicious_count', 0) * 2 + 
                    vt_result.get('suspicious_count', 0)) / 
                (vt_result.get('total_engines', 1) / 2)
            )
            shodan_risk = 0
            if shodan_result.get('vulnerable_services'):
                shodan_risk += len(shodan_result.get('vulnerable_services', [])) * 0.5
            if shodan_result.get('total_ports_open', 0) > 10:
                shodan_risk += 1
            total_risk = min(max(vt_risk + shodan_risk, 0), 10)
            return round(total_risk, 2)
        except Exception as e:
            self.logger.error(f"Risk Score Calculation Error: {e}")

    def save_url_threat(self,threat_data: Dict):
        try:
            threat = ThreatIntelligence(
                source='URL Analysis',
                threat_type='Web Threat',
                severity=threat_data.get('overall_risk_score', 0),
                indicators=[
                    threat_data.get('url', ''),
                    threat_data.get('domain', '')
                ],
                description=f"VirusTotal: {threat_data.get('virustotal', {})} | " 
                            f"Shodan: {threat_data.get('shodan', {})}"
            )
            threat.save()
        except Exception as e:
            self.logger.error(f"Threat Saving Error: {e}")