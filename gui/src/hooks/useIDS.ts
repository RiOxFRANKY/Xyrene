import { useQuery } from '@tanstack/react-query';
import { Zone, Packet, BlockedIP, Stats } from '@/lib/mock-data';

const API_BASE = 'http://127.0.0.1:9876/api';

export function useStats() {
    return useQuery<Stats>({
        queryKey: ['stats'],
        queryFn: async () => {
            const res = await fetch(`${API_BASE}/stats`);
            if (!res.ok) throw new Error('Failed to fetch stats');
            return res.json();
        },
        refetchInterval: 2000 // Poll every 2 seconds
    });
}

export function usePackets() {
    return useQuery<Packet[]>({
        queryKey: ['packets'],
        queryFn: async () => {
            const res = await fetch(`${API_BASE}/packets`);
            if (!res.ok) throw new Error('Failed to fetch packets');
            return res.json();
        },
        refetchInterval: 1000 // Poll every 1 second
    });
}

export function useBlocklist() {
    return useQuery<BlockedIP[]>({
        queryKey: ['blocks'],
        queryFn: async () => {
            const res = await fetch(`${API_BASE}/blocks`);
            if (!res.ok) throw new Error('Failed to fetch blocklist');
            return res.json();
        },
        refetchInterval: 5000 // Poll every 5 seconds
    });
}

export function useSystemLogs() {
    return useQuery<{ verdicts: string[], blocks: string[], errors: string[] }>({
        queryKey: ['system-logs'],
        queryFn: async () => {
            const res = await fetch(`${API_BASE}/system-logs`);
            if (!res.ok) throw new Error('Failed to fetch system logs');
            return res.json();
        },
        refetchInterval: 3000
    });
}

export async function blockIp(ip: string, durationSec?: number) {
    const res = await fetch(`${API_BASE}/block`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, duration_sec: durationSec })
    });
    return res.json();
}

export async function unblockIp(ip: string) {
    const res = await fetch(`${API_BASE}/unblock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
    });
    return res.json();
}

export async function startCapture() {
    const res = await fetch(`${API_BASE}/capture/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    });
    return res.json();
}

export async function stopCapture() {
    const res = await fetch(`${API_BASE}/capture/stop`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    });
    return res.json();
}
