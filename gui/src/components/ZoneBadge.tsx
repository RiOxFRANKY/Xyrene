import { Zone } from '@/lib/mock-data';
import { cn } from '@/lib/utils';

const zoneStyles: Record<string, string> = {
  BENIGN: 'zone-benign',
  SUSPICIOUS: 'zone-suspicious',
  MALICIOUS: 'zone-malicious',
  CRITICAL: 'zone-critical',
  BLOCKED: 'zone-blocked',
  MANUAL: 'zone-blocked',
};

export function ZoneBadge({ zone, className }: { zone: string; className?: string }) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider',
        zoneStyles[zone] || 'zone-benign',
        className
      )}
    >
      {zone}
    </span>
  );
}
