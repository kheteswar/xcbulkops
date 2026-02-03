import forge from 'node-forge';

export interface ParsedCertificate {
  subject: {
    commonName: string;
    organization?: string;
    unit?: string;
    country?: string;
    state?: string;
    locality?: string;
  };
  issuer: {
    commonName: string;
    organization?: string;
  };
  validFrom: Date;
  validTo: Date;
  serialNumber: string;
  sans: string[];
  isSelfSigned: boolean;
  fingerprint?: string; // SHA-1 Fingerprint
}

export const parseCertificateUrl = (certUrl: string | undefined): ParsedCertificate | null => {
  if (!certUrl || !certUrl.startsWith('string:///')) return null;

  try {
    // 1. Remove the 'string:///' prefix
    const base64Data = certUrl.replace('string:///', '');
    
    // 2. Decode Base64 to get the PEM string (contains -----BEGIN CERTIFICATE-----)
    const pem = atob(base64Data);

    // 3. Parse the PEM using node-forge (takes the first/leaf certificate)
    const cert = forge.pki.certificateFromPem(pem);

    // Helper to safely get fields
    const getField = (obj: any, name: string) => obj.getField(name)?.value;

    // 4. Extract Subject Details
    const subject = {
      commonName: getField(cert.subject, 'CN') || 'Unknown',
      organization: getField(cert.subject, 'O'),
      unit: getField(cert.subject, 'OU'),
      country: getField(cert.subject, 'C'),
      state: getField(cert.subject, 'ST'),
      locality: getField(cert.subject, 'L'),
    };

    // 5. Extract Issuer Details
    const issuer = {
      commonName: getField(cert.issuer, 'CN') || 'Unknown',
      organization: getField(cert.issuer, 'O'),
    };

    // 6. Extract SANs (Subject Alternative Names)
    const altNameExt = cert.getExtension('subjectAltName') as any;
    const sans: string[] = [];
    if (altNameExt && altNameExt.altNames) {
      altNameExt.altNames.forEach((entry: any) => {
        // type 2 is DNS, type 7 is IP
        if (entry.type === 2 || entry.type === 7) {
          sans.push(entry.value);
        }
      });
    }

    // 7. Calculate Fingerprint (optional but useful)
    const md = forge.md.sha1.create();
    md.update(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes());
    const fingerprint = md.digest().toHex().match(/.{1,2}/g)?.join(':').toUpperCase();

    return {
      subject,
      issuer,
      validFrom: cert.validity.notBefore,
      validTo: cert.validity.notAfter,
      serialNumber: cert.serialNumber,
      sans,
      isSelfSigned: cert.isIssuer(cert),
      fingerprint
    };
  } catch (err) {
    console.error("Failed to parse certificate:", err);
    return null;
  }
};