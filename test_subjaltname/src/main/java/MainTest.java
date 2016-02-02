
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;
import javax.xml.crypto.KeySelector.Purpose;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.rackspace.capman.tools.ca.RSAKeyUtils;
import org.rackspace.capman.tools.ca.CertUtils;
import org.rackspace.capman.tools.ca.PemUtils;
import org.rackspace.capman.tools.ca.primitives.Debug;

public class MainTest {

    private static final long oneMonth = 31L * 24L * 60L * 60L * 1000L;
    private static final long eightYears = 8L * 365L * 24L * 60L * 60L * 1000L;
    private static final Random rnd = new SecureRandom();

    public static void main(String[] args) {
        List<GeneralName> generalNamesList = new ArrayList<GeneralName>();
        String cnFromSubject = "C=US,ST=Texas,L=San Antonio,O=OpenStack Experiments,OU=Neutron Lbaas,CN=www.CNFromSubject.example.org";
        String cnFromAltName = "C=US,ST=Texas,L=San Antonio,O=OpenStack Experiments,OU=Neutron Lbaas,CN=";
        byte[] serialBits = new byte[128];
        rnd.nextBytes(serialBits); // Generating 128 bit random serial number to make adam happy
        try {
            long now = System.currentTimeMillis();
            System.out.printf("Generating 2048 bit key for demonstration\n");
            KeyPair kp = RSAKeyUtils.genKeyPair(2048);
            System.err.printf("Key generated\n%s\n", PemUtils.toPemString(kp));
            System.err.printf("Generating certificate\n");
            X509V3CertificateGenerator cg = new X509V3CertificateGenerator();
            cg.setSerialNumber(new BigInteger(serialBits).abs());
            cg.setNotBefore(new Date(now - oneMonth));
            cg.setNotAfter(new Date(now + eightYears));
            cg.setSubjectDN(new X509Name(cnFromSubject));
            cg.setIssuerDN(new X509Name(cnFromSubject));
            cg.setPublicKey(kp.getPublic());
            cg.setSignatureAlgorithm("sha512WithRSAEncryption");
            cg.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
            cg.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment | KeyUsage.keyAgreement));

            ASN1EncodableVector keyPurposes = new ASN1EncodableVector();
            keyPurposes.add(KeyPurposeId.id_kp_clientAuth);
            keyPurposes.add(KeyPurposeId.id_kp_serverAuth);
            keyPurposes.add(KeyPurposeId.id_kp_timeStamping);
            cg.addExtension(X509Extensions.ExtendedKeyUsage, true, new DERSequence(keyPurposes));
            System.err.printf("Adding general Names\n");
            generalNamesList.add(new GeneralName(GeneralName.dNSName, "www.hostFromdNSName1.example.com"));
            generalNamesList.add(new GeneralName(GeneralName.dNSName, "www.hostFromdNSName2.example.com"));
            generalNamesList.add(new GeneralName(GeneralName.dNSName, "www.hostFromdNSName3.example.com"));
            generalNamesList.add(new GeneralName(GeneralName.rfc822Name, "noone@example.com"));
            generalNamesList.add(new GeneralName(GeneralName.directoryName, cnFromAltName + "www.cnFromAltName1.example.com"));
            generalNamesList.add(new GeneralName(GeneralName.directoryName, cnFromAltName + "www.cnFromAltName2.example.com"));
            generalNamesList.add(new GeneralName(GeneralName.directoryName, cnFromAltName + "www.cnFromAltName3.example.com"));
            generalNamesList.add(new GeneralName(GeneralName.directoryName, cnFromAltName + "www.cnFromAltName4.example.com"));
            generalNamesList.add(new GeneralName(GeneralName.iPAddress, "10.1.2.3"));
            generalNamesList.add(new GeneralName(GeneralName.iPAddress, "0123:4567:89AB:CDEF:F7B3:D591:E6A2:C480"));
            generalNamesList.add(new GeneralName(GeneralName.uniformResourceIdentifier, "http://www.example.com"));
            generalNamesList.add(new GeneralName(GeneralName.dNSName, "www.hostFromdNSName4.example.com"));
            ASN1EncodableVector generalNamesVector = new ASN1EncodableVector();
            for (GeneralName gn : generalNamesList) {
                generalNamesVector.add(gn);
            }
            DERSequence generalNamesSequence = new DERSequence(generalNamesVector);
            cg.addExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(generalNamesSequence));
            X509Certificate x509 = cg.generateX509Certificate(kp.getPrivate(), "BC");
            System.err.printf("\nX509 created\n");
            System.out.printf("%s", PemUtils.toPemString(x509));
        } catch (Exception ex) {
            System.out.printf("Exception: Caught\n%s\n", Debug.getExtendedStackTrace(ex));
        }
    }
}
