package org.rackspace.capman.tools.util;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.rackspace.capman.tools.util.exceptions.X509PathBuildException;

// Use this one instead of X509Chainer
public class X509PathBuilder<E extends X509Certificate> {

    private Set<E> rootCAs;
    private Set<E> intermediates;

    public X509PathBuilder() {
        rootCAs = new HashSet<E>();
        intermediates = new HashSet<E>();
    }

    public X509PathBuilder(Set<E> rootCAs, Set<E> intermediates) {
        this.rootCAs = new HashSet<E>(rootCAs);
        this.intermediates = new HashSet<E>(intermediates);
    }

    public void clear() {
        rootCAs = new HashSet<E>();
        intermediates = new HashSet<E>();
    }

    public List<X509Certificate> buildPath(E userCrt) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, X509PathBuildException {
        List<X509Certificate> discoveredPath = new ArrayList<X509Certificate>();

        // Build Crt Store
        List<E> colStoreCrts = new ArrayList<E>();
        colStoreCrts.addAll(intermediates);
        colStoreCrts.add(userCrt); // Don't forget to add the End cert
        CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(colStoreCrts);
        CertStore crtStore = CertStore.getInstance("Collection", ccsp, "BC");
        X509CertSelector userCrtSelector = new X509CertSelector();
        userCrtSelector.setCertificate(userCrt);

        // Build trusted roots;
        Set<TrustAnchor> anchors = new HashSet<TrustAnchor>();
        for (E x509 : rootCAs) {
            TrustAnchor ta = new TrustAnchor(x509, null);
            anchors.add(ta);
        }

        // Setup the path builder
        PKIXBuilderParameters pbp = new PKIXBuilderParameters(anchors, userCrtSelector);
        pbp.addCertStore(crtStore);
        pbp.setRevocationEnabled(false);
        pbp.setMaxPathLength(25);

        CertPathBuilder pathBuilder = CertPathBuilder.getInstance("PKIX", "BC");
        PKIXCertPathBuilderResult buildResponse;
        try {
            buildResponse = (PKIXCertPathBuilderResult) pathBuilder.build(pbp);
        } catch (CertPathBuilderException ex) {
            throw new X509PathBuildException(ex);
        } catch (InvalidAlgorithmParameterException ex) {
            throw new X509PathBuildException(ex);
        }
        CertPath builtCrtPath = buildResponse.getCertPath();

        Iterator crtIterator = builtCrtPath.getCertificates().iterator();
        while (crtIterator.hasNext()) {
            Object obj = crtIterator.next();
            if (!(obj instanceof X509Certificate)) {
                String fmt = "Object of type %s does not appear to be a of X509Certificate or a subtype";
                String msg = String.format(fmt, obj.getClass().getSimpleName());
                throw new IllegalStateException(msg);
            } else {
                discoveredPath.add((X509Certificate) obj);
            }
        }

        return discoveredPath;
    }

    public Set<E> getRootCAs() {
        return rootCAs;
    }

    public void setRootCAs(Set<E> rootCAs) {
        this.rootCAs = rootCAs;
    }

    public Set<E> getIntermediates() {
        return intermediates;
    }

    public void setIntermediates(Set<E> intermediates) {
        this.intermediates = intermediates;
    }
}
