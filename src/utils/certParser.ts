import forge from 'node-forge';

export interface ParsedCertificate {
  subject: string;
  issuer: string;
  validFrom: Date;
  validTo: Date;
  serialNumber: string;
  sans: string[];
  isSelfSigned: boolean;
}

export const parseCertificateUrl = (certUrl: string | undefined): ParsedCertificate | null => {
  if (!certUrl || !certUrl.startsWith('string:///')) return null;

  try {
    // 1. Remove the F5 prefix
    const base64Data = certUrl.replace('string:///', '');
    
    // 2. Decode Base64 to get the PEM string
    // Note: The PEM might contain a chain; we usually care about the first (Leaf) cert.
    const pem = atob(base64Data);

    // 3. Parse the PEM using node-forge
    const cert = forge.pki.certificateFromPem(pem);

    // 4. Extract Subject Common Name
    const subjectCn = cert.subject.getField('CN')?.value || 'Unknown';
    
    // 5. Extract Issuer (simplify to CN or O)
    const issuerCn = cert.issuer.getField('CN')?.value;
    const issuerO = cert.issuer.getField('O')?.value;
    const issuerDisplay = issuerCn ? `CN=${issuerCn}` : (issuerO ? `O=${issuerO}` : 'Unknown');

    // 6. Extract SANs
    const altNameExt = cert.getExtension('subjectAltName') as any;
    const sans: string[] = altNameExt?.altNames?.map((entry: any) => entry.value) || [];

    return {
      subject: subjectCn,
      issuer: issuerDisplay,
      validFrom: cert.validity.notBefore,
      validTo: cert.validity.notAfter,
      serialNumber: cert.serialNumber,
      sans: sans,
      isSelfSigned: cert.isIssuer(cert),
    };
  } catch (err) {
    console.error("Failed to parse certificate:", err);
    return null;
  }
};