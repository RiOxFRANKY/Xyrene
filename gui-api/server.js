import express from 'express';
import cors from 'cors';
import axios from 'axios';

const app = express();
const PORT = 9876;
// Capture the dynamic Java proxy port passed by run.ps1, or fallback
const JAVA_PORT = process.env.API_PORT || 8081;
const PYTHON_API = `http://127.0.0.1:${JAVA_PORT}/api`;

app.use(cors());
app.use(express.json());

// Helper to determine threat tier color mapping equivalent
const getThreshold = (zone) => {
    switch (zone) {
        case 'SUSPICIOUS': return 5;
        case 'MALICIOUS': return 3;
        case 'CRITICAL': return 1;
        default: return 10;
    }
};

// 1. STATS ENDPOINT
app.get('/api/stats', async (req, res) => {
    try {
        const { data } = await axios.get(`${PYTHON_API}/stats`);
        
        // Transform Python _stats directly to React's mockStats structure
        const stats = {
            total_analyzed: data.total_analyzed || 0,
            total_malicious: data.malicious || 0,
            total_suspicious: data.suspicious || 0,
            total_critical: data.critical || 0,
            total_blocked: data.blocked || 0,
            false_positive_rate: parseFloat((Math.random() * 2 + 1).toFixed(1)), // Mocked FPR for dashboard flavor
            avg_malicious_confidence: 85.0, // Can be averaged from logs if needed
            model_version: 'XYRENE-v2.0.0',
            api_uptime: `${data.uptime_seconds || 0}s`,
            threats_today: (data.malicious || 0) + (data.critical || 0)
        };
        
        res.json(stats);
    } catch (error) {
        console.error('Error fetching stats:', error.message);
        res.status(500).json({ error: 'Failed to connect to ML Engine' });
    }
});

// 2. PACKETS (VERDICTS) ENDPOINT
app.get('/api/packets', async (req, res) => {
    try {
        // Fetch the last 200 logs from Python to match mock data size
        const { data } = await axios.get(`${PYTHON_API}/logs?type=verdicts&lines=200`);
        
        const packets = data.logs.filter(log => log.src_ip).map((log, index) => {
            return {
                id: log.id || `PKT-${String(index + 1).padStart(5, '0')}`,
                timestamp: log.ts || log.timestamp || new Date().toISOString(),
                src_ip: log.src_ip,
                dst_ip: log.dst_ip,
                protocol: log.protocol,
                verdict: log.verdict,
                confidence: (log.confidence || 0) * 100, // Python returns 0-1, React expects 0-100
                action: log.action,
                length: log.length,
                event_count: 1,
                ip_event_count: log.ip_event_count || 1,
                threshold: getThreshold(log.verdict)
            };
        }).reverse(); // Newest first
        
        res.json(packets);
    } catch (error) {
        console.error('Error fetching packets:', error.message);
        res.status(500).json({ error: 'Failed to fetch packet logs' });
    }
});

// 3. BLOCKS ENDPOINT
app.get('/api/blocks', async (req, res) => {
    try {
        // We get active blocks from the ML engine
        const { data: activeData } = await axios.get(`${PYTHON_API}/blocklist`);
        
        // And historical block logs to join data
        let history = [];
        try {
            const { data: logsData } = await axios.get(`${PYTHON_API}/logs?type=blocks&lines=500`);
            history = logsData.logs || [];
        } catch (e) {
            console.warn("Could not fetch block history:", e.message);
        }

        const activeMap = new Map();
        activeData.blocked_ips.forEach(b => activeMap.set(b.ip, b.expires_in_sec));
        
        const blockList = [];
        
        // Reconstruct BlockedIP instances for the table
        for (const log of history.reverse()) {
            if (log.event === 'BLOCK' && activeMap.has(log.ip)) {
                // Determine expiry date based on remaining seconds
                const expiresSec = activeMap.get(log.ip);
                const expiresDate = new Date(Date.now() + (expiresSec * 1000)).toISOString();
                
                blockList.push({
                    ip: log.ip,
                    blocked_since: log.timestamp,
                    expires: expiresDate,
                    zone: log.zone === 'MANUAL' ? 'MANUAL' : log.zone,
                    duration: log.reason
                });
                activeMap.delete(log.ip); // Only list each active IP once
            }
        }
        
        // Add any active IPs that somehow weren't in the recent log
        for (const [ip, expiresSec] of activeMap.entries()) {
            blockList.push({
                ip: ip,
                blocked_since: new Date().toISOString(),
                expires: new Date(Date.now() + (expiresSec * 1000)).toISOString(),
                zone: 'UNKNOWN',
                duration: `${Math.round(expiresSec / 60)}m`
            });
        }
        
        res.json(blockList);
    } catch (error) {
        console.error('Error fetching blocks:', error.message);
        res.status(500).json({ error: 'Failed to fetch blocklist' });
    }
});

// 4. ACTION ENDPOINTS (Proxy to Python)
app.post('/api/block', async (req, res) => {
    try {
        const { data } = await axios.post(`${PYTHON_API}/blocklist/add`, req.body);
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: 'Failed to block IP' });
    }
});

app.post('/api/unblock', async (req, res) => {
    try {
        const { data } = await axios.post(`${PYTHON_API}/blocklist/remove`, req.body);
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: 'Failed to unblock IP' });
    }
});

// 4.5 CAPTURE CONTROL ENDPOINTS (Proxy to Java)
app.post('/api/capture/start', async (req, res) => {
    try {
        const { data } = await axios.post(`${PYTHON_API}/capture/start`);
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: 'Failed to start capture' });
    }
});

app.post('/api/capture/stop', async (req, res) => {
    try {
        const { data } = await axios.post(`${PYTHON_API}/capture/stop`);
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: 'Failed to stop capture' });
    }
});

// 5. SYSTEM LOGS
app.get('/api/system-logs', async (req, res) => {
    try {
        const { data } = await axios.get(`${PYTHON_API}/logs?type=alerts&lines=50`);
        const logsData = {
            verdicts: [],
            blocks: [],
            errors: data.logs.map(l => `[${l.timestamp}] ${l.level || 'INFO'} ${l.message}`)
        };
        res.json(logsData);
    } catch (error) {
        res.json({ verdicts: [], blocks: [], errors: [] });
    }
});


app.listen(PORT, () => {
    console.log(`XYRENE GUI API Proxy running on http://127.0.0.1:${PORT}`);
    console.log(`Forwarding requests to ML Engine at ${PYTHON_API}`);
});
