// Mock data and types for the IDS dashboard

export type Zone = 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS' | 'CRITICAL' | 'BLOCKED' | 'MANUAL';

export interface Packet {
  id: string;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  protocol: string;
  verdict: Zone;
  confidence: number;
  action: string;
  length: number;
  event_count: number;
  ip_event_count: number;
  threshold: number;
}

export interface BlockedIP {
  ip: string;
  blocked_since: string;
  expires: string;
  zone: Zone;
  duration: string;
}

export interface Stats {
  total_analyzed: number;
  total_malicious: number;
  total_suspicious: number;
  total_critical: number;
  total_blocked: number;
  false_positive_rate: number;
  avg_malicious_confidence: number;
  model_version: string;
  api_uptime: string;
  threats_today: number;
}

const randomIP = () =>
  `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;

const protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'SSH'];
const zones: Zone[] = ['BENIGN', 'SUSPICIOUS', 'MALICIOUS', 'CRITICAL'];
const actions = ['ALLOW', 'FLAG', 'BLOCK', 'ALERT'];

function randomPacket(i: number): Packet {
  const zone = zones[Math.random() < 0.6 ? 0 : Math.random() < 0.5 ? 1 : Math.random() < 0.7 ? 2 : 3];
  const confidence = zone === 'BENIGN' ? Math.random() * 30 :
    zone === 'SUSPICIOUS' ? 40 + Math.random() * 25 :
    zone === 'MALICIOUS' ? 65 + Math.random() * 25 :
    90 + Math.random() * 10;
  const action = zone === 'BENIGN' ? 'ALLOW' :
    zone === 'SUSPICIOUS' ? 'FLAG' :
    zone === 'MALICIOUS' ? 'BLOCK' : 'ALERT';

  const now = new Date();
  now.setSeconds(now.getSeconds() - i * 2);

  return {
    id: `PKT-${String(10000 - i).padStart(5, '0')}`,
    timestamp: now.toISOString(),
    src_ip: randomIP(),
    dst_ip: '192.168.1.' + Math.floor(Math.random() * 254 + 1),
    protocol: protocols[Math.floor(Math.random() * protocols.length)],
    verdict: zone,
    confidence: Math.round(confidence * 10) / 10,
    action,
    length: Math.floor(Math.random() * 1500) + 40,
    event_count: Math.floor(Math.random() * 20) + 1,
    ip_event_count: Math.floor(Math.random() * 50) + 1,
    threshold: zone === 'SUSPICIOUS' ? 5 : zone === 'MALICIOUS' ? 3 : 1,
  };
}

export const mockPackets: Packet[] = Array.from({ length: 200 }, (_, i) => randomPacket(i));

export const mockBlockedIPs: BlockedIP[] = [
  { ip: '45.33.32.156', blocked_since: '2026-03-11T08:12:00Z', expires: '2026-03-11T20:12:00Z', zone: 'MALICIOUS', duration: '12h' },
  { ip: '185.220.101.34', blocked_since: '2026-03-11T07:45:00Z', expires: '2026-03-12T07:45:00Z', zone: 'CRITICAL', duration: '24h' },
  { ip: '23.129.64.100', blocked_since: '2026-03-11T06:30:00Z', expires: '2026-03-11T18:30:00Z', zone: 'SUSPICIOUS', duration: '12h' },
  { ip: '104.244.76.13', blocked_since: '2026-03-11T05:00:00Z', expires: '2026-03-11T11:00:00Z', zone: 'MALICIOUS', duration: '6h' },
  { ip: '91.219.236.222', blocked_since: '2026-03-10T22:00:00Z', expires: '2026-03-11T22:00:00Z', zone: 'MANUAL', duration: '24h' },
];

export const mockStats: Stats = {
  total_analyzed: 847293,
  total_malicious: 12847,
  total_suspicious: 34291,
  total_critical: 1893,
  total_blocked: 487,
  false_positive_rate: 2.3,
  avg_malicious_confidence: 87.4,
  model_version: 'AG3-v2.4.1-beta',
  api_uptime: '99.97%',
  threats_today: 142,
};

export const confidenceDistribution = [
  { range: '0-10%', count: 245000, color: 'hsl(131, 55%, 46%)' },
  { range: '10-20%', count: 189000, color: 'hsl(131, 55%, 46%)' },
  { range: '20-30%', count: 134000, color: 'hsl(131, 55%, 46%)' },
  { range: '30-40%', count: 98000, color: 'hsl(131, 55%, 46%)' },
  { range: '40-50%', count: 67000, color: 'hsl(131, 55%, 46%)' },
  { range: '50-60%', count: 45000, color: 'hsl(39, 87%, 49%)' },
  { range: '60-70%', count: 32000, color: 'hsl(30, 90%, 50%)' },
  { range: '70-80%', count: 18000, color: 'hsl(30, 90%, 50%)' },
  { range: '80-90%', count: 11000, color: 'hsl(30, 90%, 50%)' },
  { range: '90-100%', count: 8293, color: 'hsl(0, 93%, 63%)' },
];

export const threatDistribution = [
  { name: 'BENIGN', value: 798162, color: 'hsl(215, 10%, 45%)' },
  { name: 'SUSPICIOUS', value: 34291, color: 'hsl(39, 87%, 49%)' },
  { name: 'MALICIOUS', value: 12847, color: 'hsl(0, 93%, 63%)' },
  { name: 'CRITICAL', value: 1893, color: 'hsl(0, 93%, 50%)' },
];

export const mockLogs = {
  verdicts: Array.from({ length: 50 }, (_, i) => {
    const p = mockPackets[i];
    return `[${new Date(p.timestamp).toLocaleString()}] ${p.verdict.padEnd(12)} ${p.src_ip.padEnd(16)} → ${p.dst_ip.padEnd(16)} ${p.protocol.padEnd(6)} conf=${p.confidence}%`;
  }),
  blocks: mockBlockedIPs.map(b =>
    `[${new Date(b.blocked_since).toLocaleString()}] BLOCKED ${b.ip.padEnd(16)} zone=${b.zone} duration=${b.duration}`
  ),
  errors: [
    '[2026-03-11 08:00:12] ERROR  Model inference timeout after 5000ms — retrying',
    '[2026-03-11 07:45:33] WARN   High packet queue depth: 2847 packets pending',
    '[2026-03-11 06:12:01] ERROR  Failed to connect to threat intel API — using cached data',
    '[2026-03-11 03:00:00] INFO   Daily model reload completed successfully',
    '[2026-03-10 22:15:44] WARN   Memory usage at 87% — consider scaling',
  ],
};
