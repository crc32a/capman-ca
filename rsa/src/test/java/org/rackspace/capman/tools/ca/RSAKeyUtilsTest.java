package org.rackspace.capman.tools.ca;

import org.rackspace.capman.tools.ca.RSAKeyUtils;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.Ignore;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.rackspace.capman.tools.ca.StringUtils;
import static org.junit.Assert.*;
import org.rackspace.capman.tools.ca.primitives.RsaPair;
import org.rackspace.capman.tools.ca.exceptions.NoSuchAlgorithmException;
import org.rackspace.capman.tools.ca.exceptions.NotAnRSAKeyException;
import org.rackspace.capman.tools.ca.exceptions.PemException;
import org.rackspace.capman.tools.ca.exceptions.RsaException;

public class RSAKeyUtilsTest {

    public RSAKeyUtilsTest() {
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
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

    @Ignore
    @Test
    public void testRsaGenKey() throws RsaException {
        String msg;
        RsaPair keys = RSAKeyUtils.genRSAPair(1024,12);
        String keyStr = keys.toString();
        byte[] pem;
        String pemStr;
        try {
            pem = keys.getPrivAsPem();
            pemStr = new String(pem);
        } catch (RsaException ex) {
            msg = StringUtils.getEST(ex);
            throw ex;
        }
    }
}
