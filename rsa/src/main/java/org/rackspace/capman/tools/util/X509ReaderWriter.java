package org.rackspace.capman.tools.util;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import javax.net.ssl.SSLContext;
import org.rackspace.capman.tools.util.sslborker.TrustAllHostsVerifier;
import java.io.IOException;
import java.security.cert.Certificate;
import javax.net.ssl.HttpsURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import java.util.logging.Logger;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.jce.provider.X509CertificateObject;
import org.rackspace.capman.tools.ca.PemUtils;
import org.rackspace.capman.tools.ca.StringUtils;
import org.rackspace.capman.tools.ca.exceptions.NotAnX509CertificateException;
import org.rackspace.capman.tools.ca.exceptions.PemException;
import org.rackspace.capman.tools.ca.primitives.PemBlock;
import org.rackspace.capman.tools.ca.primitives.RsaConst;
import org.rackspace.capman.tools.util.sslborker.OverTrustingSSLContext;
import static org.rackspace.capman.tools.ca.StringUtils.asciiString;

public class X509ReaderWriter {

    private static final Logger LOG = Logger.getLogger(X509ReaderWriter.class.getName());
    private static int nopCount = 0;
    private static final int PAGESIZE = 4096;
    private static final String BEG_PRV;
    private static final String END_PRV;
    private static final String BEG_CSR;
    private static final String END_CSR;
    private static final String BEG_CRT;
    private static final String END_CRT;

    static {
        RsaConst.init();
        BEG_PRV = asciiString(PemUtils.BEG_PRV);
        BEG_CSR = asciiString(PemUtils.BEG_CSR);
        BEG_CRT = asciiString(PemUtils.BEG_CRT);
        END_PRV = asciiString(PemUtils.END_PRV);
        END_CSR = asciiString(PemUtils.END_CSR);
        END_CRT = asciiString(PemUtils.END_CRT);
    }

    public static ResponseWithExcpetions<String> writeSet(Collection<X509CertificateObject> x509objs) {
        StringBuilder sb = new StringBuilder(PAGESIZE * 4);
        List<Exception> exceptions = new ArrayList<Exception>();
        for (X509CertificateObject x509obj : x509objs) {
            try {
                String pem = PemUtils.toPemString(x509obj);
                sb.append(pem);
            } catch (PemException ex) {
                String fmt = "Object with hashcode %d "
                        + "could not be serialized to X509Certificate Pem";
                String msg = String.format(fmt, x509obj.hashCode());
                exceptions.add(buildNotX509ObjectException(msg, null, null, ex));
            }
        }
        return new ResponseWithExcpetions<String>(exceptions, sb.toString());
    }

    public static ResponseWithExcpetions<Set<X509CertificateObject>> readSet(String pemString) {
        ResponseWithExcpetions<Set<X509CertificateObject>> resp;
        List<Exception> exceptions = new ArrayList<Exception>();
        byte[] pemBytes = StringUtils.asciiBytes(pemString);
        Set<X509CertificateObject> x509objs = new HashSet<X509CertificateObject>();
        List<PemBlock> blocks = PemUtils.parseMultiPem(pemBytes);
        for (PemBlock block : blocks) {
            if (!StringUtils.strEquals(block.getStartLine(), BEG_CRT)) {
                continue;
            }
            if (block.getDecodedObject() == null) {
                exceptions.add(buildNotX509ObjectException(null, block.getLineNum(), asciiString(block.getPemData()), null));
                continue;
            }
            if (!(block.getDecodedObject() instanceof X509CertificateObject)) {
                exceptions.add(buildNotX509ObjectException(null, block.getLineNum(), asciiString(block.getPemData()), null));
                continue;
            }
            X509CertificateObject x509obj = (X509CertificateObject) block.getDecodedObject();
            x509objs.add(x509obj);
        }
        return new ResponseWithExcpetions<Set<X509CertificateObject>>(exceptions, x509objs);
    }

    private static NotAnX509CertificateException buildNotX509ObjectException(String msg, Integer lineNum, String pemString, Throwable th) {
        NotAnX509CertificateException ex;
        StringBuilder sb = new StringBuilder();
        if (msg != null) {
            sb.append(msg);
        } else {
            if (lineNum == null) {
                sb.append("Object was not an X509Certificate");
            } else {
                sb.append(String.format("Object at line %d was not an X509Certificate", lineNum.intValue()));
            }
            if (pemString != null) {
                sb.append(String.format("\n%s", pemString));
            }
        }
        if (th != null) {
            ex = new NotAnX509CertificateException(sb.toString(), th);
        } else {
            ex = new NotAnX509CertificateException(sb.toString());
        }
        return ex;
    }

    public static Collection<X509Certificate> nonPemUtilRead(String pem) throws CertificateException, NoSuchProviderException, UnsupportedEncodingException {
        Collection x509s;
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        ByteArrayInputStream bais = new ByteArrayInputStream(pem.getBytes("US-ASCII"));
        x509s = cf.generateCertificates(bais);
        return x509s;
    }

    public static List<X509CertificateObject> getX509CertificateObjectsFromUrl(String urlStr) throws IOException, NoSuchAlgorithmException, KeyManagementException {
        int i;
        List<X509CertificateObject> x509certObjs = new ArrayList<X509CertificateObject>();
        URL url = new URL(urlStr);
        HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
        SSLContext sc = OverTrustingSSLContext.newOverTrustingSSLContext("SSL");
        con.setSSLSocketFactory(sc.getSocketFactory());
        con.setHostnameVerifier(new TrustAllHostsVerifier());
        con.connect();
        Certificate[] crts = con.getServerCertificates();

        for (Certificate crt : crts) {
            String className = crt.getClass().getName();
            if (crt instanceof X509Certificate) {
                X509Certificate x509 = (X509Certificate) crt;
                String exMsg;
                try {
                    X509Inspector xi = X509Inspector.newX509Inspector(x509);
                    X509CertificateObject x509obj = xi.getX509CertificateObject();
                    x509certObjs.add(x509obj);
                } catch (CertificateEncodingException ex) {
                    logEx(ex);
                    continue;
                } catch (CertificateParsingException ex) {
                    logEx(ex);
                    continue;
                } catch (NotAnX509CertificateException ex) {
                    logEx(ex);
                    continue;
                }
            }
        }
        con.disconnect();
        return x509certObjs;
    }

    private static void logEx(Throwable th) {
        String exMsg = StringUtils.getEST(th);
        String msg = "Exception Causght: " + StringUtils.getEST(th);
        LOG.severe(msg);
    }

    public static int nop() {
        return nopCount++;
    }
}
