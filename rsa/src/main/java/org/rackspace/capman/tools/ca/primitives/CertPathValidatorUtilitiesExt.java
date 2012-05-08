package org.rackspace.capman.tools.ca.primitives;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Set;
import org.bouncycastle.jce.provider.AnnotatedException;
import org.bouncycastle.jce.provider.CertPathValidatorUtilities;

// Seems annoying that we need to extend a class to access protected Static methods
// which shoulden't have been protected in the first place
public class CertPathValidatorUtilitiesExt extends CertPathValidatorUtilities {
    public static TrustAnchor findTrustAnchor(X509Certificate crt,Set ta) throws AnnotatedException{
        return CertPathValidatorUtilities.findTrustAnchor(crt,ta);
    }

    public static TrustAnchor findTrustAnchor(X509Certificate crt,Set tas,String provider) throws AnnotatedException{
        return CertPathValidatorUtilities.findTrustAnchor(crt, tas, provider);
    }
}
