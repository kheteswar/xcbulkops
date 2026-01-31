export interface ParsedCertificate {
  subject: {
    CN?: string;
    O?: string;
    OU?: string;
    C?: string;
    ST?: string;
    L?: string;
  };
  issuer: {
    CN?: string;
    O?: string;
    OU?: string;
    C?: string;
  };
  validFrom: string;
  validTo: string;
  serialNumber: string;
  fingerprint: string;
  sans: string[];
  isExpired: boolean;
  daysUntilExpiry: number;
  keyUsage: string[];
  signatureAlgorithm: string;
}

function parseDistinguishedName(dn: string): Record<string, string> {
  const result: Record<string, string> = {};
  const parts = dn.split(/,\s*(?=[A-Z]+=)/);
  for (const part of parts) {
    const [key, ...valueParts] = part.split('=');
    if (key && valueParts.length) {
      result[key.trim()] = valueParts.join('=').trim();
    }
  }
  return result;
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

function arrayBufferToHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join(':')
    .toUpperCase();
}

export async function parsePemCertificate(pem: string): Promise<ParsedCertificate | null> {
  try {
    const pemContent = pem
      .replace(/-----BEGIN CERTIFICATE-----/g, '')
      .replace(/-----END CERTIFICATE-----/g, '')
      .replace(/\s/g, '');

    const binaryDer = base64ToArrayBuffer(pemContent);

    const cert = await crypto.subtle.importKey(
      'raw',
      binaryDer,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      true,
      []
    ).catch(() => null);

    const hashBuffer = await crypto.subtle.digest('SHA-256', binaryDer);
    const fingerprint = arrayBufferToHex(hashBuffer);

    return {
      subject: { CN: 'Certificate loaded' },
      issuer: { CN: 'Unable to parse issuer' },
      validFrom: 'Unknown',
      validTo: 'Unknown',
      serialNumber: 'Unknown',
      fingerprint: fingerprint.substring(0, 59),
      sans: [],
      isExpired: false,
      daysUntilExpiry: -1,
      keyUsage: [],
      signatureAlgorithm: 'Unknown',
    };
  } catch {
    return null;
  }
}

export function formatCertificateUrl(url: string): { type: string; location: string } {
  if (url.startsWith('string:///')) {
    return { type: 'Inline', location: 'Embedded in configuration' };
  }
  if (url.startsWith('vault://')) {
    return { type: 'Vault', location: url.replace('vault://', '') };
  }
  if (url.startsWith('wingman://')) {
    return { type: 'Wingman', location: url.replace('wingman://', '') };
  }
  return { type: 'URL', location: url };
}

export function extractCertificateFromUrl(url: string): string | null {
  if (url.startsWith('string:///')) {
    try {
      const base64 = url.replace('string:///', '');
      return atob(base64);
    } catch {
      return null;
    }
  }
  return null;
}
