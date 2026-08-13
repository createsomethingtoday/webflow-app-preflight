/**
 * Shared hostname safety checks for runtime targets.
 *
 * A hostname is considered private/local when it is localhost, an mDNS name,
 * an IPv6 literal, or any numeric IPv4 form (dotted decimal, shorthand,
 * octal, or hexadecimal) that resolves into a loopback, link-local, or
 * RFC 1918 range. Numeric forms such as `2130706433`, `0x7f000001`, and
 * `017700000001` all resolve to 127.0.0.1 in standard resolvers, so they are
 * parsed and range-checked rather than string-matched.
 */

function parseIpv4Part(part: string): number | null {
  if (/^0x[0-9a-f]+$/i.test(part)) return Number.parseInt(part.slice(2), 16);
  if (/^0[0-7]*$/.test(part)) return Number.parseInt(part, 8);
  if (/^[1-9][0-9]*$/.test(part)) return Number.parseInt(part, 10);
  return null;
}

/**
 * Returns the 32-bit IPv4 address for any numeric hostname form, or null when
 * the hostname is not a purely numeric IPv4 candidate.
 */
export function numericIpv4(hostname: string): number | null {
  const parts = hostname.split('.').filter((part) => part.length > 0);
  if (parts.length === 0 || parts.length > 4 || parts.length !== hostname.split('.').length) {
    return null;
  }
  const values = parts.map(parseIpv4Part);
  if (values.some((value) => value === null || !Number.isFinite(value))) return null;
  const numbers = values as number[];

  // The final part carries the remaining bytes; leading parts are one byte each.
  const lastMax = 2 ** (8 * (4 - (numbers.length - 1))) - 1;
  const last = numbers[numbers.length - 1]!;
  if (last < 0 || last > lastMax) return null;
  for (const value of numbers.slice(0, -1)) {
    if (value < 0 || value > 255) return null;
  }

  let address = last;
  for (let index = 0; index < numbers.length - 1; index += 1) {
    address += numbers[index]! * 2 ** (8 * (3 - index));
  }
  return address >>> 0;
}

function isPrivateIpv4Address(address: number): boolean {
  const a = (address >>> 24) & 0xff;
  const b = (address >>> 16) & 0xff;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168)
  );
}

/**
 * True when the hostname must never be used as a runtime target: localhost,
 * .local, IPv6 literals, or private/loopback IPv4 in any numeric form.
 */
export function isPrivateOrLocalHostname(hostname: string): boolean {
  const host = hostname.toLowerCase();
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) return true;
  if (host.includes(':')) return true; // IPv6 literal (URL keeps brackets/colons)
  const address = numericIpv4(host);
  return address !== null && isPrivateIpv4Address(address);
}
