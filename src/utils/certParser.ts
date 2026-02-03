import forge from 'node-forge';


export const parseCertificateUrl = (certUrl: string | undefined): ParsedCertificate | null => {
  // DEBUG 1: Check what is receiving
  console.log("[CertParser] Input URL:", certUrl ? `${certUrl.substring(0, 30)}...` : 'undefined');

  if (!certUrl || !certUrl.startsWith('string:///')) {
    console.warn("[CertParser] Invalid format or empty URL");
    return null;
  }

  try {
    // 1. Remove the F5 prefix
    const base64Data = certUrl.replace('string:///', '');
    
    // DEBUG 2: Check Base64 data length
    console.log("[CertParser] Base64 Length:", base64Data.length);

    // 2. Decode Base64
    const pem = atob(base64Data).trim();
    
    // DEBUG 3: Check if PEM looks correct (starts with -----BEGIN)
    console.log("[CertParser] Decoded PEM Start:", pem.substring(0, 40).replace(/\n/g, ' '));

    // 3. Parse using node-forge
    const cert = forge.pki.certificateFromPem(pem);

    // DEBUG 4: Check if Forge parsed it
    console.log("[CertParser] Forge Subject:", cert.subject.getField('CN')?.value);

    // ... (Keep the rest of the extraction logic exactly as before) ...
    // Extract Subject, Issuer, SANs etc.

    const result = {
      subject: { 
         commonName: cert.subject.getField('CN')?.value || 'Unknown', 
         // ... others
      },
      issuer: {
         commonName: cert.issuer.getField('CN')?.value || 'Unknown',
         // ... others
      },
      validFrom: cert.validity.notBefore,
      validTo: cert.validity.notAfter,
      serialNumber: cert.serialNumber,
      sans: [], // ... (your SANs logic)
      isSelfSigned: cert.isIssuer(cert),
      fingerprint: '...' // ... (your fingerprint logic)
    };
    
    console.log("[CertParser] Parse Success!", result);
    return result;

  } catch (err) {
    // CRITICAL DEBUG: Catch specific parsing errors
    console.error("[CertParser] CRASH:", err);
    return null;
  }
};