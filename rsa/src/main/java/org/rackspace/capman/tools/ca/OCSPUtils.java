package org.rackspace.capman.tools.ca;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;

public class OCSPUtils {

    private static final SecureRandom sr;

    static {
        SecureRandom srTmp;
        try {
            srTmp = SecureRandom.getInstance("SHA1PRNG", "SUN");
        } catch (NoSuchAlgorithmException ex) {
            srTmp = new SecureRandom();
        } catch (NoSuchProviderException ex) {
            srTmp = new SecureRandom();
        }
        sr = srTmp;
    }

    public static OCSPReq newOCSPReq(X509Certificate issuerCrt, BigInteger serial) throws OCSPException {
        SecureRandom sr = new SecureRandom();
        CertificateID crtId = new CertificateID(CertificateID.HASH_SHA1, issuerCrt, serial);
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(crtId);
        byte[] randBytes = new byte[8];
        sr.nextBytes(randBytes);
        Vector oids = new Vector();
        Vector vals = new Vector();
        oids.add(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        X509Extension ext = new X509Extension(false, new DEROctetString(randBytes));
        vals.add(ext);
        X509Extensions exts = new X509Extensions(oids, vals);
        gen.setRequestExtensions(exts);
        OCSPReq req = gen.generate();
        return req;
    }
}
