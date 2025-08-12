import google.generativeai as genai
import json
import os
from typing import Dict, List, Optional

class AIAnalyzer:
    def __init__(self, api_key: str = None):
        """Initialize AI Analyzer with Gemini API"""
        self.api_key = api_key or os.getenv('GEMINI_API_KEY')
        if not self.api_key:
            raise ValueError("Gemini API key is required. Set GEMINI_API_KEY environment variable or pass api_key parameter.")
        
        # Configure Gemini
        genai.configure(api_key=self.api_key)
        # Try different model names that might be available
        try:
            self.model = genai.GenerativeModel('gemini-1.5-flash')
        except Exception:
            try:
                self.model = genai.GenerativeModel('gemini-1.5-pro')
            except Exception:
                try:
                    self.model = genai.GenerativeModel('gemini-pro')
                except Exception as e:
                    raise ValueError(f"Could not initialize any Gemini model. Error: {str(e)}")
        
    def analyze_payload_intelligence(self, payload_data: Dict[str, str]) -> Dict[str, str]:
        """Analyze payload data using AI to identify threats and patterns"""
        try:
            # Prepare payload summary for AI analysis
            payload_summary = []
            for ip, payload in payload_data.items():
                if payload and len(payload.strip()) > 10:
                    payload_summary.append(f"IP: {ip} | Payload: {payload[:200]}...")
            
            if not payload_summary:
                return {"analysis": "No meaningful payload data found for AI analysis"}
            
            # Create AI prompt
            prompt = f"""
            Analyze these network packet payloads for security threats and patterns:
            
            {chr(10).join(payload_summary[:20])}  # Limit to first 20 for API efficiency
            
            Provide analysis in JSON format with the following structure:
            {{
                "threat_level": "low/medium/high",
                "threats_detected": ["list of specific threats"],
                "protocols_identified": ["list of protocols"],
                "suspicious_patterns": ["list of suspicious patterns"],
                "recommendations": ["list of security recommendations"],
                "summary": "brief summary of findings"
            }}
            
            Focus on identifying:
            - Malicious payloads
            - Data exfiltration attempts
            - Command and control traffic
            - Unusual protocols or ports
            - Encrypted or obfuscated content
            """
            
            response = self.model.generate_content(prompt)
            return json.loads(response.text)
            
        except Exception as e:
            return {"error": f"AI analysis failed: {str(e)}"}
    
    def analyze_network_behavior(self, analysis_data: Dict) -> Dict[str, str]:
        """Analyze overall network behavior and patterns"""
        try:
            # Prepare network summary
            vpn_count = sum(1 for data in analysis_data.values() if data.get("VPN Status") is True)
            total_ips = len(analysis_data)
            countries = set(data.get("Country", "") for data in analysis_data.values() if data.get("Country"))
            
            # Create AI prompt
            prompt = f"""
            Analyze this network traffic data for security insights:
            
            Network Summary:
            - Total IPs: {total_ips}
            - VPN IPs: {vpn_count}
            - Countries: {len(countries)} ({', '.join(list(countries)[:10])})
            
            Provide analysis in JSON format:
            {{
                "risk_assessment": "low/medium/high",
                "anomalies_detected": ["list of anomalies"],
                "geographic_analysis": "analysis of geographic distribution",
                "vpn_analysis": "analysis of VPN usage patterns",
                "security_implications": ["list of security implications"],
                "recommendations": ["list of recommendations"]
            }}
            
            Consider:
            - Geographic distribution of traffic
            - VPN usage patterns
            - Unusual country combinations
            - Potential data exfiltration
            - Compliance implications
            """
            
            response = self.model.generate_content(prompt)
            return json.loads(response.text)
            
        except Exception as e:
            return {"error": f"Network behavior analysis failed: {str(e)}"}
    
    def generate_threat_report(self, analysis_data: Dict, payload_data: Dict) -> str:
        """Generate comprehensive threat report using AI"""
        try:
            # Prepare comprehensive data summary
            summary = {
                "total_ips": len(analysis_data),
                "vpn_ips": sum(1 for data in analysis_data.values() if data.get("VPN Status") is True),
                "countries": list(set(data.get("Country", "") for data in analysis_data.values() if data.get("Country"))),
                "payloads_analyzed": len([p for p in payload_data.values() if p and len(p.strip()) > 10])
            }
            
            prompt = f"""
            Generate a comprehensive cybersecurity threat report based on this network analysis:
            
            Analysis Summary:
            {json.dumps(summary, indent=2)}
            
            Create a professional threat report with:
            1. Executive Summary
            2. Key Findings
            3. Threat Assessment
            4. Risk Analysis
            5. Recommendations
            6. Technical Details
            
            Format as a structured report with clear sections and actionable insights.
            """
            
            response = self.model.generate_content(prompt)
            return response.text
            
        except Exception as e:
            return f"Error generating threat report: {str(e)}"
    
    def analyze_specific_ip(self, ip: str, ip_data: Dict) -> Dict[str, str]:
        """Analyze a specific IP address for threats"""
        try:
            prompt = f"""
            Analyze this IP address for security threats:
            
            IP: {ip}
            VPN Status: {ip_data.get('VPN Status', 'Unknown')}
            Country: {ip_data.get('Country', 'Unknown')}
            City: {ip_data.get('City', 'Unknown')}
            ISP: {ip_data.get('ISP', 'Unknown')}
            MAC: {ip_data.get('MAC Address', 'Unknown')}
            Fingerprint: {ip_data.get('Fingerprint Info', 'Unknown')}
            
            Provide analysis in JSON format:
            {{
                "threat_level": "low/medium/high",
                "risk_factors": ["list of risk factors"],
                "geographic_risk": "assessment of geographic risk",
                "isp_analysis": "analysis of ISP",
                "recommendations": ["specific recommendations"],
                "investigation_priority": "high/medium/low"
            }}
            """
            
            response = self.model.generate_content(prompt)
            return json.loads(response.text)
            
        except Exception as e:
            return {"error": f"IP analysis failed: {str(e)}"}
    
    def explain_technical_findings(self, technical_data: str) -> str:
        """Explain technical findings in simple terms"""
        try:
            prompt = f"""
            Explain this technical network analysis finding in simple, non-technical terms:
            
            {technical_data}
            
            Provide a clear explanation that a non-technical person can understand, including:
            - What it means
            - Why it's important
            - What actions should be taken
            """
            
            response = self.model.generate_content(prompt)
            return response.text
            
        except Exception as e:
            return f"Error explaining findings: {str(e)}"

def get_ai_analyzer(api_key: str = None) -> Optional[AIAnalyzer]:
    """Get AI analyzer instance if API key is available"""
    try:
        # If no API key provided, try to get from config
        if api_key is None:
            from config import Config
            api_key = Config.GEMINI_API_KEY
        
        return AIAnalyzer(api_key)
    except ValueError:
        print("Warning: Gemini API key not found. AI analysis features will be disabled.")
        print("Set GEMINI_API_KEY environment variable or pass api_key parameter to enable AI features.")
        return None
