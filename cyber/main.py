"""
Attack Path Intelligence Engine - Main Entry Point
"""
import argparse
from pathlib import Path
from typing import List
from collections import defaultdict

# Import all components
from ingestors import *
from normalizer import VulnerabilityNormalizer
from enrichment import EnrichmentEngine
from attack_graph import AttackGraphBuilder, AttackPathGenerator
from zero_day import ZDESCalculator, AnomalyDetector, ExploitBehaviorDetector
from correlation import CorrelationEngine
from reports import JSONExporter, PDFReportGenerator, HTMLDashboardGenerator, GraphVisualizer
from models.schemas import Asset, NormalizedVulnerability
from utils.logger import engine_logger
from utils.config import config

class AttackPathEngine:
    """Main engine orchestrating all components"""
    
    def __init__(self):
        self.logger = engine_logger
        self.logger.info("Initializing Attack Path Intelligence Engine")
        
        # Initialize components
        self.parsers = {
            'nmap': NmapParser(),
            'rustscan': RustScanParser(),
            'masscan': MasscanParser(),
            'naabu': NaabuParser(),
            'nuclei': NucleiParser(),
            'wapiti': WapitiParser(),
            'nikto': NiktoParser(),
            'trivy': TrivyParser(),
            'openvas': OpenVASParser(),
            'nessus': NessusParser()
        }
        
        self.normalizer = VulnerabilityNormalizer()
        self.enrichment_engine = EnrichmentEngine()
        self.graph_builder = AttackGraphBuilder()
        self.zdes_calculator = ZDESCalculator()
        self.anomaly_detector = AnomalyDetector()
        self.exploit_behavior_detector = ExploitBehaviorDetector()
        self.correlation_engine = CorrelationEngine()
        
        # Reporters
        self.json_exporter = JSONExporter()
        self.pdf_generator = PDFReportGenerator()
        self.html_generator = HTMLDashboardGenerator()
        self.graph_visualizer = GraphVisualizer()
    
    def run(self, scan_files: dict, output_formats: list = ['json', 'pdf', 'html']):
        """
        Main execution flow
        
        Args:
            scan_files: Dict mapping scanner names to file paths
            output_formats: List of desired output formats
        """
        
        self.logger.info("=" * 80)
        self.logger.info("ATTACK PATH INTELLIGENCE ENGINE - STARTING ANALYSIS")
        self.logger.info("=" * 80)
        
        # Step 1: Ingest scan data
        self.logger.info("\n[STEP 1] Ingesting scan data...")
        raw_vulnerabilities = self._ingest_scans(scan_files)
        self.logger.info(f"Ingested {len(raw_vulnerabilities)} raw findings")
        
        # Step 2: Normalize data
        self.logger.info("\n[STEP 2] Normalizing vulnerability data...")
        normalized_vulns = self.normalizer.normalize(raw_vulnerabilities)
        normalized_vulns = self.normalizer.deduplicate_by_cve(normalized_vulns)
        self.logger.info(f"Normalized to {len(normalized_vulns)} unique vulnerabilities")
        
        # Step 3: Enrich with threat intelligence
        self.logger.info("\n[STEP 3] Enriching with threat intelligence...")
        enriched_vulns = self.enrichment_engine.bulk_enrich_epss(normalized_vulns)
        enriched_vulns = self.enrichment_engine.enrich_all(enriched_vulns)
        self.logger.info("Enrichment complete")
        
        # Step 4: Build attack graph
        self.logger.info("\n[STEP 4] Building attack graph...")
        attack_graph = self.graph_builder.build_graph(enriched_vulns)
        self.logger.info(f"Attack graph: {attack_graph.number_of_nodes()} nodes, {attack_graph.number_of_edges()} edges")
        
        # Step 5: Generate attack paths
        self.logger.info("\n[STEP 5] Generating attack paths...")
        path_generator = AttackPathGenerator(attack_graph)
        attack_paths = path_generator.generate_all_paths()
        self.logger.info(f"Generated {len(attack_paths)} attack paths")
        
        # Step 6: Create asset objects and calculate ZDES
        self.logger.info("\n[STEP 6] Calculating Zero-Day Exposure Scores...")
        assets = self._create_assets(enriched_vulns)
        self._calculate_zdes_scores(assets, enriched_vulns)
        self.logger.info(f"Calculated ZDES for {len(assets)} assets")
        
        # Step 7: Detect anomalies
        self.logger.info("\n[STEP 7] Detecting anomalies...")
        anomaly_indicators = self.anomaly_detector.detect_anomalies(enriched_vulns)
        self.logger.info(f"Detected {len(anomaly_indicators)} anomalies")
        
        # Step 8: Detect exploit behaviors
        self.logger.info("\n[STEP 8] Analyzing exploit behaviors...")
        behavior_indicators = self.exploit_behavior_detector.detect_suspicious_behaviors(
            attack_paths, enriched_vulns
        )
        self.logger.info(f"Detected {len(behavior_indicators)} suspicious behaviors")
        
        # Combine all zero-day indicators
        all_zd_indicators = anomaly_indicators + behavior_indicators
        
        # Step 9: Correlate all data
        self.logger.info("\n[STEP 9] Correlating all intelligence sources...")
        correlation_results = self.correlation_engine.correlate_all(
            enriched_vulns, assets, attack_paths, all_zd_indicators
        )
        self.logger.info(f"Network Risk Score: {correlation_results['network_risk_score']:.1f}/100")
        
        # Step 10: Generate reports
        self.logger.info("\n[STEP 10] Generating reports...")
        report_files = self._generate_reports(
            enriched_vulns, attack_paths, all_zd_indicators, 
            correlation_results, attack_graph, output_formats
        )
        
        self.logger.info("\n" + "=" * 80)
        self.logger.info("ANALYSIS COMPLETE")
        self.logger.info("=" * 80)
        self.logger.info("\nGenerated Reports:")
        for format_type, filepath in report_files.items():
            self.logger.info(f"  - {format_type.upper()}: {filepath}")
        
        return correlation_results
    
    def _ingest_scans(self, scan_files: dict) -> List[NormalizedVulnerability]:
        """Ingest all scan files"""
        all_vulnerabilities = []
        
        for scanner_name, file_path in scan_files.items():
            if scanner_name not in self.parsers:
                self.logger.warning(f"Unknown scanner: {scanner_name}")
                continue
            
            if not Path(file_path).exists():
                self.logger.warning(f"File not found: {file_path}")
                continue
            
            self.logger.info(f"Parsing {scanner_name}: {file_path}")
            parser = self.parsers[scanner_name]
            vulns = parser.parse(file_path)
            all_vulnerabilities.extend(vulns)
            self.logger.info(f"  → Found {len(vulns)} findings")
        
        return all_vulnerabilities
    
    def _create_assets(self, vulnerabilities: List[NormalizedVulnerability]) -> List[Asset]:
        """Create asset objects from vulnerabilities"""
        asset_map = defaultdict(lambda: {
            'hostname': None,
            'ip_address': None,
            'os': None,
            'services': [],
            'vulnerabilities': []
        })
        
        for vuln in vulnerabilities:
            asset_data = asset_map[vuln.asset_id]
            
            if not asset_data['hostname'] and vuln.hostname:
                asset_data['hostname'] = vuln.hostname
            if not asset_data['ip_address'] and vuln.ip_address:
                asset_data['ip_address'] = vuln.ip_address
            if not asset_data['os'] and vuln.os:
                asset_data['os'] = vuln.os
            
            if vuln.service_name:
                service_info = {
                    'name': vuln.service_name,
                    'port': vuln.port,
                    'version': vuln.service_version
                }
                if service_info not in asset_data['services']:
                    asset_data['services'].append(service_info)
            
            asset_data['vulnerabilities'].append(vuln)
        
        # Create Asset objects
        assets = []
        for asset_id, data in asset_map.items():
            asset = Asset(
                asset_id=asset_id,
                hostname=data['hostname'],
                ip_address=data['ip_address'],
                os=data['os'],
                services=data['services'],
                vulnerabilities=data['vulnerabilities']
            )
            assets.append(asset)
        
        return assets
    
    def _calculate_zdes_scores(self, assets: List[Asset], 
                              vulnerabilities: List[NormalizedVulnerability]):
        """Calculate ZDES scores for all assets"""
        for asset in assets:
            asset_vulns = [v for v in vulnerabilities if v.asset_id == asset.asset_id]
            asset.zdes_score = self.zdes_calculator.calculate_zdes(asset, asset_vulns)
    
    def _generate_reports(self, vulnerabilities, attack_paths, zero_day_indicators,
                         correlation_results, attack_graph, output_formats):
        """Generate all requested report formats"""
        report_files = {}
        
        if 'json' in output_formats:
            json_file = self.json_exporter.export_complete_report(
                vulnerabilities, attack_paths, zero_day_indicators, correlation_results
            )
            report_files['json'] = json_file
        
        if 'pdf' in output_formats:
            pdf_file = self.pdf_generator.generate_report(correlation_results)
            report_files['pdf'] = pdf_file
        
        if 'html' in output_formats:
            html_file = self.html_generator.generate_dashboard(correlation_results)
            report_files['html'] = html_file
        
        # Always generate graph visualizations
        graph_png = self.graph_visualizer.visualize_attack_graph(attack_graph)
        graph_d3 = self.graph_visualizer.generate_d3_html(attack_graph)
        report_files['graph_png'] = graph_png
        report_files['graph_d3'] = graph_d3
        
        return report_files


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(
        description='Attack Path Intelligence Engine - Comprehensive Vulnerability Analysis'
    )
    
    parser.add_argument('--nmap', help='Nmap XML file')
    parser.add_argument('--rustscan', help='RustScan JSON file')
    parser.add_argument('--masscan', help='Masscan XML/JSON file')
    parser.add_argument('--naabu', help='Naabu JSON file')
    parser.add_argument('--nuclei', help='Nuclei JSON file')
    parser.add_argument('--wapiti', help='Wapiti JSON file')
    parser.add_argument('--nikto', help='Nikto TXT/JSON file')
    parser.add_argument('--trivy', help='Trivy JSON file')
    parser.add_argument('--openvas', help='OpenVAS XML file')
    parser.add_argument('--nessus', help='Nessus XML file')
    
    parser.add_argument('--output', '-o', nargs='+', 
                       choices=['json', 'pdf', 'html', 'all'],
                       default=['all'],
                       help='Output formats (default: all)')
    
    parser.add_argument('--config', '-c', help='Config file path', default='config.yaml')
    
    args = parser.parse_args()
    
    # Collect scan files
    scan_files = {}
    for scanner in ['nmap', 'rustscan', 'masscan', 'naabu', 'nuclei', 
                   'wapiti', 'nikto', 'trivy', 'openvas', 'nessus']:
        file_path = getattr(args, scanner, None)
        if file_path:
            scan_files[scanner] = file_path
    
    if not scan_files:
        parser.error("At least one scan file must be provided")
    
    # Determine output formats
    output_formats = args.output
    if 'all' in output_formats:
        output_formats = ['json', 'pdf', 'html']
    
    # Load config
    if args.config:
        config.load_config(args.config)
    
    # Run engine
    engine = AttackPathEngine()
    engine.run(scan_files, output_formats)


if __name__ == '__main__':
    main()
