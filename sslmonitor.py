#!/usr/bin/env python3
"""
sslmonitor.py - Certificate Expiration Monitoring and Alerting

Usage:
  sslmonitor.py -c config.yaml
  sslmonitor.py -f domains.txt --slack-webhook https://...

Config file example (config.yaml):
  targets:
    - google.com
    - github.com:443
    - smtp://gmail.com:587
  alerting:
    threshold_days: 30
    slack_webhook: "https://hooks.slack.com/services/..."
    email:
      server: smtp.example.com
      port: 587
      user: alerts@example.com
      password: "env:SMTP_PASSWORD"
      to: ops@example.com
"""

import argparse
import sys
import yaml
import json
import os
import requests
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Import extraction logic
from sslxtract import SSLExtractor, get_expiration_date, parse_target
from sslutils import parse_target as robust_parse_target

class Alerter:
    def __init__(self, config):
        self.config = config
        self.threshold = config.get('alerting', {}).get('threshold_days', 30)
        self.slack_url = config.get('alerting', {}).get('slack_webhook')
        self.email_conf = config.get('alerting', {}).get('email')

    def send_slack(self, failures, expiring):
        if not self.slack_url:
            return

        blocks = []
        
        if failures:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": "🚨 *SSL Monitor Failures* 🚨"}
            })
            for f in failures:
                blocks.append({
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"❌ *{f['target']}*: {f['error']}"}
                })

        if expiring:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": "⚠️ *Expiring Certificates* ⚠️"}
            })
            for e in expiring:
                days = e['days']
                icon = "🔥" if days < 7 else "⚠️"
                blocks.append({
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"{icon} *{e['target']}*: Expires in {days} days ({e['date']})"}
                })

        if not blocks:
            return

        payload = {"blocks": blocks}
        try:
            requests.post(self.slack_url, json=payload, timeout=10)
        except Exception as e:
            print(f"Failed to send Slack alert: {e}", file=sys.stderr)

    def send_email(self, failures, expiring):
        if not self.email_conf:
            return

        try:
            recipients = self.email_conf.get('to', [])
            if isinstance(recipients, str):
                recipients = [recipients]
            if not recipients:
                raise ValueError("email alerting requires at least one 'to' recipient")

            lines = []
            for failure in failures:
                lines.append(f"FAILURE: {failure['target']}: {failure['error']}")
            for item in expiring:
                lines.append(f"EXPIRING: {item['target']}: {item['days']} days ({item['date']})")

            message = MIMEText('\n'.join(lines))
            message['Subject'] = self.email_conf.get('subject', 'SSL certificate monitor alert')
            message['From'] = self.email_conf.get('from') or self.email_conf.get('user') or 'sslmonitor@localhost'
            message['To'] = ', '.join(recipients)

            password = self.email_conf.get('password')
            if isinstance(password, str) and password.startswith('env:'):
                password = os.environ.get(password[4:])
            if self.email_conf.get('ssl', False):
                client = smtplib.SMTP_SSL(self.email_conf['server'], self.email_conf.get('port', 465), timeout=10)
            else:
                client = smtplib.SMTP(self.email_conf['server'], self.email_conf.get('port', 587), timeout=10)
                if self.email_conf.get('starttls', True):
                    client.starttls()
            with client:
                if self.email_conf.get('user'):
                    client.login(self.email_conf['user'], password or '')
                client.sendmail(message['From'], recipients, message.as_string())
        except Exception as e:
            print(f"Failed to send email alert: {e}", file=sys.stderr)

    def run(self, results):
        failures = [r for r in results if not r['success']]
        expiring = []
        for r in results:
            if r['success'] and r.get('days_left') is not None:
                if r['days_left'] < self.threshold:
                    expiring.append({
                        'target': r['target'],
                        'days': r['days_left'],
                        'date': r.get('expires', 'Unknown')
                    })
        
        if failures or expiring:
            self.send_slack(failures, expiring)
            self.send_email(failures, expiring)
            return True # Alerts triggered
        return False

def check_target(target):
    extractor = SSLExtractor(timeout=10)
    try:
        # Use robust parser
        host, port, proto = robust_parse_target(target)
        der, _ = extractor.extract(host, port, proto)
        
        if not der:
            return {'target': target, 'success': False, 'error': 'No certificate received'}
            
        info = get_expiration_date(der)
        days = info.get('days_until_expiry')
        
        return {
            'target': target,
            'success': True,
            'days_left': days,
            'expires': info.get('notAfter'),
            'subject': info.get('subject')
        }
    except Exception as e:
        return {'target': target, 'success': False, 'error': str(e)}

def main():
    parser = argparse.ArgumentParser(description='SSL Certificate Monitor')
    parser.add_argument('-c', '--config', help='Config file (YAML/JSON)')
    parser.add_argument('-f', '--file', help='List of domains to check')
    parser.add_argument('--slack-webhook', help='Slack Webhook URL')
    parser.add_argument('--threshold', type=int, default=30, help='Days warning threshold')
    parser.add_argument('--json-log', action='store_true', help='Output JSON logs for ingestion')
    
    args = parser.parse_args()
    
    config = {'targets': [], 'alerting': {}}
    
    # Load config file
    if args.config:
        with open(args.config) as f:
            if args.config.endswith('.json'):
                config = json.load(f)
            else:
                config = yaml.safe_load(f)
    
    # Merge CLI args
    if args.file:
        with open(args.file) as f:
            config['targets'].extend([l.strip() for l in f if l.strip()])
            
    if args.slack_webhook:
        config['alerting']['slack_webhook'] = args.slack_webhook
        
    config['alerting']['threshold_days'] = args.threshold
    
    if not config['targets']:
        print("No targets specified", file=sys.stderr)
        sys.exit(1)
        
    # Execute checks
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_target, t): t for t in config['targets']}
        for f in futures:
            results.append(f.result())
            
    # Alerting
    alerter = Alerter(config)
    alerts_sent = alerter.run(results)
    
    # Output
    if args.json_log:
        for r in results:
            print(json.dumps(r))
    else:
        print(f"Checked {len(results)} targets.")
        if alerts_sent:
            print("⚠️ Alerts triggered!")
        else:
            print("✅ All systems go.")

if __name__ == '__main__':
    main()
