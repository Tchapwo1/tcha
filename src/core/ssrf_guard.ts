import * as dns from 'dns/promises';
import { URL } from 'url';

/**
 * Checks whether an IPv4 address falls within private/cloud metadata ranges.
 */
function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(isNaN)) return true;

  // 127.0.0.0/8 (Loopback)
  if (parts[0] === 127) return true;
  // 10.0.0.0/8 (Private)
  if (parts[0] === 10) return true;
  // 172.16.0.0/12 (Private)
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  // 192.168.0.0/16 (Private)
  if (parts[0] === 192 && parts[1] === 168) return true;
  // 169.254.0.0/16 (Link-local & AWS/GCP/Azure Metadata)
  if (parts[0] === 169 && parts[1] === 254) return true;
  // 100.64.0.0/10 (CGNAT)
  if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true;
  // 0.0.0.0/8
  if (parts[0] === 0) return true;

  return false;
}

function isPrivateIPv6(ip: string): boolean {
  const normalized = ip.toLowerCase().replace(/^\[|\]$/g, '');
  // ::1 (Loopback) or :: (unspecified)
  if (normalized === '::1' || normalized === '0:0:0:0:0:0:0:1' || normalized === '::') return true;
  // fe80::/10 (Link-local)
  if (normalized.startsWith('fe8') || normalized.startsWith('fe9') || normalized.startsWith('fea') || normalized.startsWith('feb')) return true;
  // fc00::/7 (Unique local)
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true;
  // IPv4-mapped IPv6 (::ffff:127.0.0.1)
  if (normalized.includes('::ffff:')) {
    const ipv4Part = normalized.split('::ffff:')[1];
    if (ipv4Part && isPrivateIPv4(ipv4Part)) return true;
  }

  return false;
}

function parseHexOrDecimalIP(hostname: string): string | null {
  const clean = hostname.replace(/^\[|\]$/g, '');
  if (clean.startsWith('0x') || clean.startsWith('0X')) {
    const num = parseInt(clean, 16);
    if (!isNaN(num)) {
      return `${(num >> 24) & 255}.${(num >> 16) & 255}.${(num >> 8) & 255}.${num & 255}`;
    }
  }
  if (/^\d+$/.test(clean)) {
    const num = parseInt(clean, 10);
    if (!isNaN(num) && num >= 0 && num <= 4294967295) {
      return `${(num >> 24) & 255}.${(num >> 16) & 255}.${(num >> 8) & 255}.${num & 255}`;
    }
  }
  return null;
}

export class SSRFGuardTS {
  public static async isSafeUrl(rawUrl: string): Promise<{ safe: boolean; reason: string }> {
    try {
      const parsed = new URL(rawUrl);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return { safe: false, reason: `Unsupported protocol ${parsed.protocol}` };
      }

      let hostname = parsed.hostname.toLowerCase();

      // Check local domain names immediately
      if (
        hostname === 'localhost' ||
        hostname.endsWith('.localhost') ||
        hostname.endsWith('.local') ||
        hostname.endsWith('.internal') ||
        hostname.endsWith('.lan')
      ) {
        return { safe: false, reason: `Hostname '${hostname}' matches internal domain policy.` };
      }

      // Check hex/decimal encoded IPs
      const convertedIp = parseHexOrDecimalIP(hostname);
      if (convertedIp && isPrivateIPv4(convertedIp)) {
        return { safe: false, reason: `Target IP ${hostname} (${convertedIp}) is private or loopback.` };
      }

      // Direct IP check
      if (isPrivateIPv4(hostname) || isPrivateIPv6(hostname)) {
        return { safe: false, reason: `Target IP ${hostname} is private or link-local metadata.` };
      }

      // DNS lookup
      const addresses = await dns.lookup(hostname, { all: true });
      for (const addr of addresses) {
        if (addr.family === 4 && isPrivateIPv4(addr.address)) {
          return { safe: false, reason: `DNS for ${hostname} resolved to forbidden IPv4 ${addr.address}` };
        }
        if (addr.family === 6 && isPrivateIPv6(addr.address)) {
          return { safe: false, reason: `DNS for ${hostname} resolved to forbidden IPv6 ${addr.address}` };
        }
      }

      return { safe: true, reason: 'URL targets authorized public IP.' };
    } catch (err: any) {
      return { safe: false, reason: `SSRF validation error: ${err.message}` };
    }
  }
}
