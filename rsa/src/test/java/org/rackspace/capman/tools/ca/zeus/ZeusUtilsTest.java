/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.rackspace.capman.tools.ca.zeus;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.rackspace.capman.tools.ca.PemUtils;
import org.rackspace.capman.tools.ca.StringUtils;
import org.rackspace.capman.tools.ca.exceptions.NotAnX509CertificateException;
import org.rackspace.capman.tools.ca.exceptions.PemException;
import org.rackspace.capman.tools.ca.exceptions.RsaException;
import org.rackspace.capman.tools.ca.exceptions.X509PathBuildException;
import org.rackspace.capman.tools.ca.primitives.PemBlock;
import org.rackspace.capman.tools.ca.zeus.ZeusUtils;
import org.rackspace.capman.tools.ca.zeus.ZeusUtils;
import org.rackspace.capman.tools.ca.zeus.primitives.ErrorEntry;
import org.rackspace.capman.tools.ca.zeus.primitives.ZeusCrtFile;
import org.rackspace.capman.tools.util.StaticHelpers;
import org.rackspace.capman.tools.util.X509BuiltPath;
import org.rackspace.capman.tools.util.X509ChainEntry;
import org.rackspace.capman.tools.util.X509PathBuilder;
import org.rackspace.capman.tools.util.fileio.RsaFileUtils;

public class ZeusUtilsTest {

    private static KeyPair userKey;
    private static X509CertificateObject userCrt;
    private static Set<X509CertificateObject> imdCrts;
    private static X509CertificateObject rootCA;
    private static int keySize = 512; // Keeping the key small for testing
    private static List<X509ChainEntry> chainEntries;

    static {
    }

    public ZeusUtilsTest() {
    }

    @BeforeClass
    public static void setUpClass() throws RsaException, NotAnX509CertificateException {
        long now = System.currentTimeMillis();
        long lastYear = now - (long) 1000 * 24 * 60 * 60 * 365;
        long nextYear = now + (long) 1000 * 24 * 60 * 60 * 365;
        Date notBefore = new Date(lastYear);
        Date notAfter = new Date(nextYear);
        String wtf = String.format("%s\n%s", StaticHelpers.getDateString(notBefore), StaticHelpers.getDateString(notAfter));
        List<String> subjNames = new ArrayList<String>();
        // Root SubjName
        subjNames.add("CN=RootCA");

        // Add the middle subjs
        for (int i = 1; i <= 7; i++) {
            String fmt = "CN=Intermedite Cert %s";
            String subjName = String.format(fmt, i);
            subjNames.add(subjName);
        }

        // Lastly add the end user subj
        String subjName = "CN=www.junit-mosso-apache2zeus-test.com";
        subjNames.add(subjName);
        chainEntries = X509PathBuilder.newChain(subjNames, keySize, notBefore, notAfter);
        int lastIdx = chainEntries.size() - 1;
        rootCA = chainEntries.get(0).getX509obj();
        userCrt = chainEntries.get(lastIdx).getX509obj();
        userKey = chainEntries.get(lastIdx).getKey();

        imdCrts = new HashSet<X509CertificateObject>();
        for (int i = 1; i < lastIdx; i++) {
            imdCrts.add(chainEntries.get(i).getX509obj());
        }
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    @Test
    public void testZeusCertFile() throws X509PathBuildException, PemException {
        StringBuilder wtf = new StringBuilder(4096);
        StringBuilder sb = new StringBuilder(4096);
        Set<X509CertificateObject> roots = new HashSet<X509CertificateObject>();
        String rootCaStr = PemUtils.toPemString(rootCA);
        roots.add(rootCA);
        String userKeyStr = PemUtils.toPemString(userKey);
        String userCrtStr = PemUtils.toPemString(userCrt);
        List<X509CertificateObject> imdCrtsReversed = new ArrayList(imdCrts);
        Collections.reverse(imdCrtsReversed);
        for (X509CertificateObject x509obj : imdCrtsReversed) {
            sb.append(PemUtils.toPemString(x509obj));
        }
        String imdsString = sb.toString();
        ZeusUtils zu = new ZeusUtils(roots);
        ZeusCrtFile zcf = zu.buildZeusCrtFile(userKeyStr, userCrtStr, imdsString,false);
        for (ErrorEntry errors : zcf.getErrors()) {
            Throwable ex = errors.getException();
            if (ex != null) {
                wtf.append(StringUtils.getEST(ex));
            }
        }

        assertTrue(zcf.getErrors().isEmpty());
        List<PemBlock> parsedImds = PemUtils.parseMultiPem(imdsString);
        assertTrue(parsedImds.size() == 7);
        for (PemBlock block : parsedImds) {
            assertTrue(block.getDecodedObject() instanceof X509CertificateObject);
        }
    }
}
