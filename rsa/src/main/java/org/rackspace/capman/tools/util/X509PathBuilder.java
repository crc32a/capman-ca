package org.rackspace.capman.tools.util;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.AnnotatedException;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.rackspace.capman.tools.ca.CertUtils;
import org.rackspace.capman.tools.ca.CsrUtils;
import org.rackspace.capman.tools.ca.RSAKeyUtils;
import org.rackspace.capman.tools.ca.exceptions.NotAnX509CertificateException;
import org.rackspace.capman.tools.ca.exceptions.RsaCsrException;
import org.rackspace.capman.tools.ca.exceptions.RsaException;

import org.rackspace.capman.tools.ca.primitives.RsaConst;
import org.rackspace.capman.tools.ca.exceptions.X509PathBuildException;

// Use this one instead of X509Chainer
public class X509PathBuilder<E extends X509Certificate> {

    private Set<E> rootCAs;
    private Set<E> intermediates;

    static {
        RsaConst.init();
    }

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

    public X509BuiltPath<E> buildPath(E userCrt) throws X509PathBuildException {
        return buildPath(userCrt, null);
    }

    public X509BuiltPath<E> buildPath(E userCrt, Date date) throws X509PathBuildException {
        List<E> discoveredPath = new ArrayList<E>();

        // Build Crt Store
        Set<E> colStoreCrts = new HashSet<E>();
        colStoreCrts.addAll(intermediates);
        colStoreCrts.add(userCrt); // Don't forget to add the End cert
        colStoreCrts.removeAll(rootCAs); // rootCAs are the endpoint so remove them incase they are in the intermediates
        CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(colStoreCrts);
        CertStore crtStore;
        try {
            crtStore = CertStore.getInstance("Collection", ccsp, "BC");
        } catch (InvalidAlgorithmParameterException ex) {
            throw new X509PathBuildException("InvalidAlgorithmParemeter when initializing CollectionStore", ex);
        } catch (NoSuchAlgorithmException ex) {
            throw new X509PathBuildException("NoSuchAlgorithmException when initializing CollectionStore", ex);
        } catch (NoSuchProviderException ex) {
            throw new X509PathBuildException("NoSuchProviderException when initializing CollectionStore", ex);
        }
        X509CertSelector userCrtSelector = new X509CertSelector();
        userCrtSelector.setCertificate(userCrt);

        // Build trusted roots;
        Set<TrustAnchor> anchors = new HashSet<TrustAnchor>();
        for (E x509 : rootCAs) {
            TrustAnchor ta = new TrustAnchor(x509, null);
            anchors.add(ta);
        }

        // Setup the path builder
        PKIXBuilderParameters pbp;
        try {
            pbp = new PKIXBuilderParameters(anchors, userCrtSelector);
        } catch (InvalidAlgorithmParameterException ex) {
            throw new X509PathBuildException("InvalidAlgorithmParameter when initializing PKIXBuilderParameters", ex);
        }
        pbp.addCertStore(crtStore);
        pbp.setRevocationEnabled(false);
        pbp.setMaxPathLength(25);
        pbp.setDate(date);

        CertPathBuilder pathBuilder;
        try {
            pathBuilder = CertPathBuilder.getInstance("PKIX", "BC");
        } catch (NoSuchAlgorithmException ex) {
            throw new X509PathBuildException("NoSuchAlgorithmException when initializing pathBuilder", ex);
        } catch (NoSuchProviderException ex) {
            throw new X509PathBuildException("NoSuchProviderException when initializing pathBuilder", ex);
        }
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
                discoveredPath.add((E) obj);
            }
        }
        TrustAnchor topAnchor;
        TrustAnchor mostTrustedAnchor = buildResponse.getTrustAnchor();
        Object obj = mostTrustedAnchor.getTrustedCert();
        E topCrt = (E) mostTrustedAnchor.getTrustedCert();
        X509BuiltPath<E> builtPath = new X509BuiltPath<E>(discoveredPath, topCrt);
        return builtPath;
    }

    // Usefull for pretending to be a CA when you want to test a Chain
    public static List<X509ChainEntry> newChain(List<String> subjNames, int keySize, Date notBefore, Date notAfter, int secDelta) throws NotAnX509CertificateException, RsaException {
        List<X509ChainEntry> chain = new ArrayList<X509ChainEntry>();
        Date before = new Date(notBefore.getTime());
        Date after = new Date(notAfter.getTime());
        BigInteger serial = new BigInteger("2");
        X509ChainEntry subjEntry ;
        long delta = (long) secDelta * 1000;
        int userIdx = subjNames.size() - 1;
        X509CertificateObject caCrt, crt;
        PKCS10CertificationRequest csr;
        KeyPair sigKey, key;
        String subj;

        key = RSAKeyUtils.genKeyPair(keySize);
        subj = subjNames.get(0);
        csr = CsrUtils.newCsr(subj, key, true);
        X509Certificate obj = CertUtils.selfSignCsrCA(csr, key, before, after);
        if (!(obj instanceof X509CertificateObject)) {
            throw new NotAnX509CertificateException();
        }
        crt = (X509CertificateObject) obj;
        subjEntry  = new X509ChainEntry(key, csr, crt);
        chain.add(subjEntry );
        for (int i = 1; i <= userIdx; i++) {
            subj = subjNames.get(i);
            key = RSAKeyUtils.genKeyPair(1024);
            csr = CsrUtils.newCsr(subj, key, true);
            before = new Date(before.getTime() + delta);
            after = new Date(after.getTime() - delta);
            sigKey = chain.get(chain.size() - 1).getKey();
            caCrt = chain.get(chain.size() - 1).getX509obj();
            obj = CertUtils.signCSR(csr, sigKey, caCrt, before, after, serial);
            if (!(obj instanceof X509CertificateObject)) {
                throw new NotAnX509CertificateException();
            }
            crt = (X509CertificateObject) obj;
            X509ChainEntry sigEntry = chain.get(chain.size()-1);
            subjEntry  = new X509ChainEntry(key, csr, crt);
            chain.add(subjEntry );
        }
        return chain;
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
