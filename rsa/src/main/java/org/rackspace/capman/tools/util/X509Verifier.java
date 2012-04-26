package org.rackspace.capman.tools.util;

import org.bouncycastle.jce.provider.X509CertificateObject;
import org.rackspace.capman.tools.ca.RSAKeyUtils;
import org.rackspace.capman.tools.ca.CertUtils;
import java.security.KeyPair;
import java.util.List;


// Simple class that merges functionality from CertUtils and KeyUtils
public class X509Verifier {

    static List<String> verifyKeyAndCert(KeyPair kp, X509CertificateObject crt) {
        return RSAKeyUtils.verifyKeyAndCert(kp, crt);
    }

    static List<String> verifyIssuerAndSubjectCert(X509CertificateObject issuerCrt, X509CertificateObject subjectCrt) {
        return CertUtils.verifyIssuerAndSubjectCert(issuerCrt, issuerCrt);
        
    }

}
