
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
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
import org.rackspace.capman.tools.ca.RSAKeyUtils;
import org.rackspace.capman.tools.ca.CertUtils;
import org.rackspace.capman.tools.ca.PemUtils;
import org.rackspace.capman.tools.ca.primitives.Debug;

public class MainTest {

    private static final long oneMonthMillis = 24L * 60L * 60L * 1000L;

    public static void main(String[] args) {
        List<GeneralName> generalNamesList = new ArrayList<GeneralName>();
        String cnFromSubject = "C=US,ST=Texas,L=San Antonio,O=OpenStack Experiments,OU=Neutron Lbaas,CN=www.CNFromSubject.org";
        String cnFromAltName = "C=US,ST=Texas,L=San Antonio,O=OpenStack Experiments,OU=Neutron Lbaas,CN=";
        try {
            long now = System.currentTimeMillis();
            System.out.printf("Generating 2048 bit key for demonstration\n");
            KeyPair kp = RSAKeyUtils.genKeyPair(2048);
            System.err.printf("Key generated\n%s\n", PemUtils.toPemString(kp));
            System.err.printf("Generating certificate\n");
            X509V3CertificateGenerator cg = new X509V3CertificateGenerator();
            cg.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
            cg.setNotBefore(new Date(now - oneMonthMillis));
            cg.setNotAfter(new Date(now + oneMonthMillis));
            cg.setSubjectDN(new X509Name(cnFromSubject));
            cg.setIssuerDN(new X509Name(cnFromSubject));
            cg.setPublicKey(kp.getPublic());
            cg.setSignatureAlgorithm("sha512WithRSAEncryption");
            cg.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
            cg.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment | KeyUsage.keyAgreement));
            System.err.printf("Adding general Names\n");
            generalNamesList.add(new GeneralName(GeneralName.dNSName, "www.hostFrom_dNSName1.com"));
            generalNamesList.add(new GeneralName(GeneralName.dNSName, "www.hostFrom_dNSName2.com"));
            generalNamesList.add(new GeneralName(GeneralName.dNSName, "www.hostFrom_dNSName3.com"));
            generalNamesList.add(new GeneralName(GeneralName.rfc822Name, "noone@nowhere.org"));
            generalNamesList.add(new GeneralName(GeneralName.directoryName, cnFromAltName + "www.cnFromAltName1.org"));
            generalNamesList.add(new GeneralName(GeneralName.directoryName, cnFromAltName + "www.cnFromAltName2.org"));
            generalNamesList.add(new GeneralName(GeneralName.directoryName, cnFromAltName + "www.cnFromAltName3.org"));
            generalNamesList.add(new GeneralName(GeneralName.directoryName, cnFromAltName + "www.cnFromAltName4.org"));
            generalNamesList.add(new GeneralName(GeneralName.iPAddress, "10.1.2.3"));
            generalNamesList.add(new GeneralName(GeneralName.iPAddress, "0123:4567:89AB:CDEF:F7B3:D591:E6A2:C480"));
            generalNamesList.add(new GeneralName(GeneralName.uniformResourceIdentifier, "http://www.example.com"));
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
