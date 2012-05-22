package org.rackspace.capman.tools.util;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.jce.provider.X509CertificateObject;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.rackspace.capman.tools.ca.exceptions.NotAnX509CertificateException;
import org.rackspace.capman.tools.ca.exceptions.PemException;
import org.rackspace.capman.tools.ca.exceptions.PrivKeyDecodeException;
import org.rackspace.capman.tools.ca.exceptions.PrivKeyDecodeException;
import org.rackspace.capman.tools.ca.exceptions.PrivKeyDecodeException;
import org.rackspace.capman.tools.ca.exceptions.PrivKeyDecodeException;
import org.rackspace.capman.tools.ca.exceptions.PrivKeyDecodeException;
import org.rackspace.capman.tools.ca.primitives.RsaConst;
import org.rackspace.capman.tools.ca.primitives.RsaPair;
import org.rackspace.capman.tools.ca.RSAKeyUtils;
import org.rackspace.capman.tools.ca.CertUtils;
import org.junit.Assert;
import org.rackspace.capman.tools.ca.exceptions.X509ReaderDecodeException;

public class X509VerifierTest {

    private X509Inspector caCrtReader;
    private X509Inspector testCrtReader;
    private X509Inspector pkcs8CrtReader;
    private PrivKeyReader caKeyReader;
    private PrivKeyReader testKeyReader;
    private PrivKeyReader pkcs8KeyReader;
    public static final List<String> dateErrorFilter;
    
    static {
        dateErrorFilter = new ArrayList<String>();
        dateErrorFilter.add(CertUtils.ISSUER_NOT_AFTER_FAIL);
        dateErrorFilter.add(CertUtils.ISSUER_NOT_BEFORE_FAIL);
        dateErrorFilter.add(CertUtils.SUBJECT_NOT_AFTER_FAIL);
        dateErrorFilter.add(CertUtils.SUBJECT_NOT_BEFORE_FAIL);
    }

    public X509VerifierTest() {
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @Before
    public void setUp() throws X509ReaderDecodeException, NotAnX509CertificateException, PrivKeyDecodeException  {
        RsaConst.init();
        caCrtReader = X509Inspector.newX509Inspector(X509InspectorTest.caCrtPem);
        testCrtReader = X509Inspector.newX509Inspector(X509InspectorTest.testCrtPem);
        pkcs8CrtReader = X509Inspector.newX509Inspector(X509InspectorTest.pkcs8CrtPem);

        caKeyReader = PrivKeyReader.newPrivKeyReader(PrivKeyReaderTest.caKeyPem);
        testKeyReader = PrivKeyReader.newPrivKeyReader(PrivKeyReaderTest.testKeyPem);
        pkcs8KeyReader = PrivKeyReader.newPrivKeyReader(PrivKeyReaderTest.pkcs8);
    }

    @After
    public void tearDown() {
    }

    private List<String> verifyIssuerAndSubjectCertWhoCaresAboutTheDate(X509CertificateObject issuerCrt,X509CertificateObject subjectCrt){
        List<String> errorList = X509Verifier.verifyIssuerAndSubjectCert(issuerCrt, subjectCrt);
        errorList.removeAll(dateErrorFilter); // Don't count Date Errors since who know
        return errorList; // other wise these tests will fail around 2039
    }

    public void caCrtShouldHaveSignedtestCrt() {
        X509CertificateObject caCrt = caCrtReader.getX509CertificateObject();
        X509CertificateObject testCrt = testCrtReader.getX509CertificateObject();
        List<String> errorList = verifyIssuerAndSubjectCertWhoCaresAboutTheDate(caCrt, testCrt);
        Assert.assertEquals(0, errorList.size());
    }

    @Test
    public void caCrtAlsoShouldHaveSignedPkcs8Crt() {
        X509CertificateObject caCrt = caCrtReader.getX509CertificateObject();
        X509CertificateObject pkcs8Crt = pkcs8CrtReader.getX509CertificateObject();
        List<String> errorList =verifyIssuerAndSubjectCertWhoCaresAboutTheDate(caCrt, pkcs8Crt);
        Assert.assertEquals(0, errorList.size());
    }

    @Test
    public void pkcs8CrtDidntSignTestCrtOnTheOtherHand() {
        X509CertificateObject pkcs8Crt = pkcs8CrtReader.getX509CertificateObject();
        X509CertificateObject testCrt = testCrtReader.getX509CertificateObject();
        List<String> errorList = verifyIssuerAndSubjectCertWhoCaresAboutTheDate(testCrt, pkcs8Crt);
        Assert.assertTrue(errorList.size() > 0); // This should error out
    }

    @Test
    public void pkcs8CrtShouldMatchPkcs8Key() {
        KeyPair kp = pkcs8KeyReader.toKeyPair();
        X509CertificateObject pkcs8Crt = pkcs8CrtReader.getX509CertificateObject();
        List<String> errorList = X509Verifier.verifyKeyAndCert(kp, pkcs8Crt);
        Assert.assertEquals(0, errorList.size());
    }

    @Test
    public void caKeyShouldMatchCaCrt() {
        KeyPair kp = caKeyReader.toKeyPair();
        X509CertificateObject caCrt = caCrtReader.getX509CertificateObject();
        List<String> errorList = X509Verifier.verifyKeyAndCert(kp, caCrt);
        Assert.assertEquals(0, errorList.size());
    }

    @Test
    public void caKeyShouldMisMatchTestCrt() {
        KeyPair kp = caKeyReader.toKeyPair();
        X509CertificateObject testCrt = testCrtReader.getX509CertificateObject();
        List<String> errorList = X509Verifier.verifyKeyAndCert(kp, testCrt);
        Assert.assertTrue(errorList.size()>0);
    }

}
