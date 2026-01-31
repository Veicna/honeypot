#!/usr/bin/env python3
import json
from pathlib import Path
from collections import Counter
import datetime
import argparse


class LogAnalyzer:
    
    def __init__(self, log_dir="logs"):
        self.log_dir = Path(log_dir)
        self.attacks = []
        self.load_logs()
    
    def load_logs(self):
        json_log = self.log_dir / "honeypot_events.json"
        
        if not json_log.exists():
            print(f"Log file not found: {json_log}")
            return
        
        with open(json_log, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    event = json.loads(line)
                    if event.get("level") == "ALERT":
                        self.attacks.append(event)
                except:
                    pass
    
    def print_summary(self):
        print("\n" + "="*70)
        print("HONEYPOT ATTACK REPORT")
        print("="*70)
        
        if not self.attacks:
            print("\nNo attacks detected yet.")
            return
        
        print(f"\nTotal Attacks: {len(self.attacks)}")
        
        service_counts = Counter(attack['data']['service'] for attack in self.attacks)
        print("\nAttacks by Service:")
        for service, count in service_counts.most_common():
            print(f"   • {service:10} : {count} attacks")
        
        ip_counts = Counter(attack['data']['attacker_ip'] for attack in self.attacks)
        print("\nTop Attackers (IP):")
        for ip, count in ip_counts.most_common(10):
            print(f"   • {ip:15} : {count} attacks")
        
        hours = Counter(
            datetime.datetime.strptime(attack['timestamp'], "%Y-%m-%d %H:%M:%S").hour
            for attack in self.attacks
        )
        print("\nAttacks by Hour:")
        for hour in sorted(hours.keys()):
            bar = "█" * min(hours[hour], 50)
            print(f"   {hour:02d}:00 : {bar} ({hours[hour]})")
    
    def print_detailed_attacks(self, limit=20):
        print("\n" + "="*70)
        print(f"DETAILED ATTACK LOG (Last {limit})")
        print("="*70)
        
        for i, attack in enumerate(self.attacks[-limit:], 1):
            data = attack['data']
            print(f"\n#{i} - {attack['timestamp']}")
            print(f"   Service   : {data['service']}")
            print(f"   IP        : {data['attacker_ip']}")
            print(f"   Port      : {data['port']}")
            print(f"   Data      : {data['data'][:100]}...")
    
    def export_to_csv(self, output_file="honeypot_report.csv"):
        import csv
        
        output_path = self.log_dir / output_file
        
        with open(output_path, "w", newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'Service', 'Attacker IP', 'Port', 'Data'])
            
            for attack in self.attacks:
                data = attack['data']
                writer.writerow([
                    attack['timestamp'],
                    data['service'],
                    data['attacker_ip'],
                    data['port'],
                    data['data'][:200]
                ])
        
        print(f"\nCSV report created: {output_path}")
    
    def get_statistics(self):
        if not self.attacks:
            return {}
        
        service_counts = Counter(attack['data']['service'] for attack in self.attacks)
        ip_counts = Counter(attack['data']['attacker_ip'] for attack in self.attacks)
        
        return {
            'total_attacks': len(self.attacks),
            'unique_ips': len(ip_counts),
            'services_attacked': dict(service_counts),
            'top_attackers': dict(ip_counts.most_common(5)),
            'first_attack': self.attacks[0]['timestamp'],
            'last_attack': self.attacks[-1]['timestamp']
        }


def print_banner():
    banner = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║         HoneyPot Log Analysis & Reporting Tool            ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
"""
    print(banner)


def main():
    parser = argparse.ArgumentParser(description='HoneyPot Log Analyzer')
    parser.add_argument('--log-dir', default='logs', help='Log directory')
    parser.add_argument('--export-csv', action='store_true', help='Export CSV report')
    parser.add_argument('--detailed', action='store_true', help='Show detailed attacks')
    parser.add_argument('--limit', type=int, default=20, help='Max attacks to show')
    
    args = parser.parse_args()
    
    print_banner()
    
    analyzer = LogAnalyzer(log_dir=args.log_dir)
    
    analyzer.print_summary()
    
    if args.detailed:
        analyzer.print_detailed_attacks(limit=args.limit)
    
    if args.export_csv:
        analyzer.export_to_csv()
    
    stats = analyzer.get_statistics()
    if stats:
        print("\n" + "="*70)
        print("STATISTICS")
        print("="*70)
        print(f"  Total Attacks      : {stats['total_attacks']}")
        print(f"  Unique IPs         : {stats['unique_ips']}")
        print(f"  First Attack       : {stats['first_attack']}")
        print(f"  Last Attack        : {stats['last_attack']}")
    
    print("\n")


if __name__ == "__main__":
    main()
