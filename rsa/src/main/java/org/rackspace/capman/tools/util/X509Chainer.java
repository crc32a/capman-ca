package org.rackspace.capman.tools.util;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

// Nieve chain builder.
public class X509Chainer {
    private List<X509Certificate>x509Certs;

    public X509Chainer(){
    }

    // Nieve O(n) based search. IF you use it for path building it could become
    // O(n*l) where l is the length of the chain
    public List<X509Certificate> getNextIssuer(X509Certificate subjectCert){
        List<X509Certificate> nextIssuer = new ArrayList<X509Certificate>();
        for(X509Certificate candidateCrt : x509Certs){
            PublicKey candidateKey = (PublicKey) candidateCrt.getPublicKey();
            try {
                subjectCert.verify(candidateKey);
            } catch (CertificateException ex) {
                continue;
            } catch (NoSuchAlgorithmException ex) {
                continue;
            } catch (InvalidKeyException ex) {
                continue;
            } catch (NoSuchProviderException ex) {
                continue;
            } catch (SignatureException ex) {
                continue;
            }
            // Looks like we found a hit
            nextIssuer.add(candidateCrt);
        }
        return nextIssuer;
    }

    public List<X509Certificate> getX509Certs() {
        return x509Certs;
    }

    public void setX509Certs(List<X509Certificate> x509Certs) {
        this.x509Certs = x509Certs;
    }
}
