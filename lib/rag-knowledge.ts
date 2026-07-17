// RAG (Retrieval-Augmented Generation) Knowledge Base
// This is the cybersecurity knowledge layer

export interface KnowledgeEntry {
  attackType: string;
  title: string;
  description: string;
  howItWorks: string;
  indicators: string[];
  impact: string;
  prevention: string[];
  mitigation: string[];
  tools: string[];
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
}

// Cybersecurity Knowledge Base
const knowledgeBase: KnowledgeEntry[] = [
  {
    attackType: 'DDoS',
    title: 'Distributed Denial of Service (DDoS) Attack',
    description: 'A DDoS attack floods a network, server, or service with excessive traffic to overwhelm resources and cause denial of service for legitimate users.',
    howItWorks: 'Attackers use a network of compromised computers (botnet) to send massive amounts of requests to the target simultaneously, exhausting bandwidth, CPU, or memory.',
    indicators: [
      'Unusually high traffic volume from multiple IPs',
      'Slow network performance',
      'Server timeout errors (504, 503)',
      'High CPU/memory usage',
      'Multiple requests to same endpoint'
    ],
    impact: 'Service downtime, revenue loss, reputational damage, increased operational costs, potential data loss',
    prevention: [
      'Use a CDN with DDoS protection (Cloudflare, Akamai)',
      'Implement rate limiting on API endpoints',
      'Deploy Web Application Firewall (WAF)',
      'Use load balancers to distribute traffic',
      'Enable auto-scaling to handle traffic spikes'
    ],
    mitigation: [
      'Block attacking IPs at network level',
      'Enable DDoS protection mode',
      'Increase server capacity temporarily',
      'Filter malicious traffic using firewall rules',
      'Activate emergency rate limiting'
    ],
    tools: ['Cloudflare DDoS Protection', 'AWS Shield', 'Azure DDoS Protection', 'Imperva', 'Radware'],
    severity: 'High'
  },
  {
    attackType: 'Brute Force',
    title: 'Brute Force Attack',
    description: 'A brute force attack attempts to gain unauthorized access by systematically trying many password combinations until the correct one is found.',
    howItWorks: 'Attackers use automated tools to try thousands or millions of password combinations against login endpoints, often using common passwords or dictionary words.',
    indicators: [
      'Multiple failed login attempts from same IP',
      'High volume of POST requests to /login',
      'Unusual login times (off-hours)',
      'Same IP trying different usernames',
      'Rapid successive requests'
    ],
    impact: 'Account takeover, data breach, unauthorized access, credential theft, lateral movement within network',
    prevention: [
      'Implement account lockout after 5 failed attempts',
      'Use CAPTCHA after multiple failures',
      'Enforce strong password policies',
      'Enable Multi-Factor Authentication (MFA)',
      'Use rate limiting on authentication endpoints'
    ],
    mitigation: [
      'Temporarily block attacking IP',
      'Reset compromised account passwords',
      'Review access logs for unauthorized entries',
      'Notify affected users',
      'Implement progressive delays between attempts'
    ],
    tools: ['Fail2ban', 'Google reCAPTCHA', 'Auth0', 'Okta', 'Cloudflare Bot Management'],
    severity: 'High'
  },
  {
    attackType: 'Bot Traffic',
    title: 'Bot Traffic / Web Scraping',
    description: 'Automated bot traffic that scrapes content, submits spam, or performs automated actions that degrade service quality.',
    howItWorks: 'Attackers deploy scripts or bots that mimic human behavior to extract data, submit forms, or abuse API endpoints at scale.',
    indicators: [
      'High request volume from single IP',
      'Unusual user-agent strings',
      'Requests without proper headers',
      'Sub-second request intervals',
      'Accessing patterns not typical for humans'
    ],
    impact: 'Server overload, data theft, skewed analytics, spam content, API abuse, competitive disadvantage',
    prevention: [
      'Implement CAPTCHA on forms',
      'Use bot detection services',
      'Require JavaScript execution',
      'Implement honey pot fields',
      'Rate limit by IP and session'
    ],
    mitigation: [
      'Block known bot IP ranges',
      'Challenge suspicious requests with CAPTCHA',
      'Implement behavioral analysis',
      'Use bot management solutions',
      'Rotate API keys for legitimate bots'
    ],
    tools: ['Cloudflare Bot Management', 'DataDome', 'Imperva Bot Protection', 'reCAPTCHA v3', 'Akamai Bot Manager'],
    severity: 'Medium'
  },
  {
    attackType: 'Port Scan',
    title: 'Port Scan / Network Reconnaissance',
    description: 'Attackers scan network ports to discover open services, operating systems, and potential vulnerabilities before launching an attack.',
    howItWorks: 'Attackers use tools like Nmap to send packets to various ports, analyzing responses to identify open ports, services, and potential entry points.',
    indicators: [
      'Connections to many different ports from same IP',
      'Unusual port sequences (sequential scanning)',
      'Connection attempts to non-standard ports',
      'SYN packets without completing handshake',
      'Multiple half-open connections'
    ],
    impact: 'Information disclosure, vulnerability identification, attack preparation, compliance violations',
    prevention: [
      'Use firewall to block unnecessary ports',
      'Implement port knocking',
      'Deploy IDS/IPS to detect scanning',
      'Use network segmentation',
      'Disable unused services'
    ],
    mitigation: [
      'Block scanning IP addresses',
      'Add to threat intelligence feed',
      'Increase logging on targeted ports',
      'Implement rate limiting on connection attempts',
      'Use honeypots to identify scanners'
    ],
    tools: ['Snort', 'Suricata', 'Fail2ban', 'pfSense', 'CrowdSec'],
    severity: 'Medium'
  },
  {
    attackType: 'Unknown Intrusion',
    title: 'Unknown / Suspicious Intrusion',
    description: 'Unusual network activity that doesn\'t match known attack patterns but exhibits suspicious characteristics requiring investigation.',
    howItWorks: 'The activity shows anomalies in traffic patterns, unusual data transfers, or connections to suspicious external addresses that warrant further analysis.',
    indicators: [
      'Connection to known malicious IPs',
      'Unusual data transfer volumes',
      'Abnormal protocol usage',
      'Non-standard port usage',
      'Geographic anomalies'
    ],
    impact: 'Potential data exfiltration, malware communication, unauthorized access, pending attack preparation',
    prevention: [
      'Maintain updated threat intelligence feeds',
      'Implement zero-trust architecture',
      'Use network segmentation',
      'Deploy endpoint detection and response (EDR)',
      'Regular security audits'
    ],
    mitigation: [
      'Isolate affected systems immediately',
      'Capture network traffic for analysis',
      'Review logs for related activity',
      'Scan for malware',
      'Update detection rules'
    ],
    tools: ['Wireshark', 'Zeek (Bro)', 'Security Onion', 'ELK Stack', 'Splunk'],
    severity: 'High'
  }
];

// RAG Retrieval Function
export function retrieveKnowledge(attackType: string): KnowledgeEntry | null {
  // Find matching knowledge entry
  const entry = knowledgeBase.find(k => 
    k.attackType.toLowerCase() === attackType.toLowerCase()
  );
  
  return entry || null;
}

// Get all attack types
export function getAllAttackTypes(): string[] {
  return knowledgeBase.map(k => k.attackType);
}

// Search knowledge base by keyword
export function searchKnowledge(keyword: string): KnowledgeEntry[] {
  const lowerKeyword = keyword.toLowerCase();
  return knowledgeBase.filter(k => 
    k.title.toLowerCase().includes(lowerKeyword) ||
    k.description.toLowerCase().includes(lowerKeyword) ||
    k.indicators.some(i => i.toLowerCase().includes(lowerKeyword))
  );
}

// Get mitigation steps for an attack
export function getMitigationSteps(attackType: string): string[] {
  const entry = retrieveKnowledge(attackType);
  return entry?.mitigation || ['Monitor the situation', 'Check logs for more information'];
}

// Get prevention recommendations
export function getPreventionTips(attackType: string): string[] {
  const entry = retrieveKnowledge(attackType);
  return entry?.prevention || ['Keep systems updated', 'Use firewall protection'];
}