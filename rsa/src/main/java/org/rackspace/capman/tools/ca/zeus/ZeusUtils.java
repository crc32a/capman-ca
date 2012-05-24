package org.rackspace.capman.tools.ca.zeus;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.HackedProviderAccessor;
import org.bouncycastle.jce.provider.JCERSAPrivateCrtKey;
import org.bouncycastle.jce.provider.JCERSAPublicKey;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.rackspace.capman.tools.ca.CertUtils;
import org.rackspace.capman.tools.ca.PemUtils;
import org.rackspace.capman.tools.ca.exceptions.PemException;
import org.rackspace.capman.tools.ca.exceptions.X509PathBuildException;
import org.rackspace.capman.tools.ca.primitives.PemBlock;
import org.rackspace.capman.tools.ca.primitives.RsaConst;
import org.rackspace.capman.tools.ca.zeus.primitives.ErrorEntry;
import org.rackspace.capman.tools.ca.zeus.primitives.ErrorType;
import org.rackspace.capman.tools.ca.zeus.primitives.ZeusCrtFile;
import org.rackspace.capman.tools.util.ResponseWithExcpetions;
import org.rackspace.capman.tools.util.StaticHelpers;
import org.rackspace.capman.tools.util.X509BuiltPath;
import org.rackspace.capman.tools.util.X509PathBuilder;
import org.rackspace.capman.tools.util.X509ReaderWriter;

public class ZeusUtils {

    private Set<X509CertificateObject> roots;

    public ZeusUtils() {
        roots = new HashSet<X509CertificateObject>();
    }

    public ZeusUtils(Set<X509CertificateObject> roots) {
        this.roots = roots;
    }

    public ZeusCrtFile buildZeusCrtFile(String keyStr, String userCrtStr, String intermediates) {
        Date date = new Date(System.currentTimeMillis());
        return buildZeusCrtFile(keyStr, userCrtStr, intermediates, date);
    }

    public ZeusCrtFile buildZeusCrtFile(String keyStr, String userCrtStr, String intermediates, Date date) {
        ZeusCrtFile zcf = new ZeusCrtFile();
        List<ErrorEntry> errors = zcf.getErrors();
        List<PemBlock> blocks;
        KeyPair kp = null;
        X509CertificateObject userCrt = null;
        Object obj;
        // Read Key
        kp = parseKey(keyStr, errors);
        userCrt = parseCert(userCrtStr, errors);

        if (userCrt != null) {
            if (CertUtils.isCertExpired(userCrt, date)) {
                Date after = userCrt.getNotAfter();
                String errorMsg = invalidDateMessage("User cert expired on", after);
                errors.add(new ErrorEntry(ErrorType.EXPIRED_CERT, errorMsg, false, null));
            }

            if (CertUtils.isCertPremature(userCrt, date)) {
                Date before = userCrt.getNotBefore();
                String errorMsg = invalidDateMessage("User cert isn't valid till", date);
                errors.add(new ErrorEntry(ErrorType.PREMATURE_CERT, errorMsg, false, null));
            }
        }

        // Check key and cert match
        if (kp != null && userCrt != null) {
            PublicKey userKey = userCrt.getPublicKey();
            List<ErrorEntry> keyCrtErrors = CertUtils.validateKeyMatchesCert((JCERSAPublicKey) kp.getPublic(), userCrt);
            if (keyCrtErrors.size() > 0) {
                errors.addAll(keyCrtErrors);
                return zcf;
            }
        }
        // Retrieve Intermediates.
        Set<X509CertificateObject> imdSet;
        if (intermediates != null) {
            ResponseWithExcpetions<Set<X509CertificateObject>> resp = X509ReaderWriter.readSet(intermediates);
            imdSet = resp.getReturnObject();
            for (Throwable th : resp.getExceptions()) {
                errors.add(new ErrorEntry(ErrorType.UNREADABLE_CERT, th.getMessage(), false, th));
            }
        } else {
            imdSet = new HashSet<X509CertificateObject>();
        }

        if (userCrt != null) {
            X509PathBuilder<X509CertificateObject> pathBuilder = new X509PathBuilder<X509CertificateObject>(roots, imdSet);
            X509BuiltPath<X509CertificateObject> builtPath;
            try {
                builtPath = pathBuilder.buildPath(userCrt, date);
            } catch (X509PathBuildException ex) {
                errors.add(new ErrorEntry(ErrorType.NO_PATH_TO_ROOT, "No Path to root", true, ex));
                return zcf;
            }
            StringBuilder sb = new StringBuilder(RsaConst.PAGESIZE);
            List<ErrorEntry> certWriteErrors = new ArrayList<ErrorEntry>();
            for (X509CertificateObject x509obj : builtPath.getPath()) {
                try {
                    String x509String = PemUtils.toPemString(x509obj);
                    sb.append(x509String);
                } catch (PemException ex) {
                    certWriteErrors.add(new ErrorEntry(ErrorType.COULDENT_ENCODE_CERT, "Coulden't encode intermediate", true, ex));
                }
                if (certWriteErrors.size() > 0) {
                    errors.addAll(certWriteErrors);
                    return zcf;
                }
            }
        }
        if (kp != null) {
            try {
                String privKey = PemUtils.toPemString(kp);
                zcf.setPrivate_key(privKey);
            } catch (PemException ex) {
                errors.add(new ErrorEntry(ErrorType.COULDENT_ENCODE_KEY, ex.getMessage(), true, ex));
                return zcf;
            }
        }
        return zcf;
    }

    public Set<X509CertificateObject> getRoots() {
        return roots;
    }

    public void setRoots(Set<X509CertificateObject> roots) {
        this.roots = roots;
    }

    private static KeyPair parseKey(String keyIn, List<ErrorEntry> errors) {
        KeyPair kp = null;
        List<PemBlock> blocks = PemUtils.parseMultiPem(keyIn);
        Object obj;
        if (blocks.size() < 1) {
            errors.add(new ErrorEntry(ErrorType.UNREADABLE_KEY, "No pemblock found in key String", true, null));
            return kp;
        }

        if (blocks.size() > 1) {
            errors.add(new ErrorEntry(ErrorType.UNREADABLE_KEY, "Multiple pem blocks used in Key", true, null));
            return kp;
        }
        obj = blocks.get(0).getDecodedObject();
        if (obj == null) {
            errors.add(new ErrorEntry(ErrorType.UNREADABLE_KEY, "Unable to parse pemblock to RSA object", true, null));
            return kp;
        }
        if (obj instanceof JCERSAPrivateCrtKey) {
            obj = HackedProviderAccessor.newKeyPair((JCERSAPrivateCrtKey) obj);
        }
        if (!(obj instanceof KeyPair)) {
            errors.add(new ErrorEntry(ErrorType.UNREADABLE_KEY, "Unable to parse pemblock to RSA object", true, null));
            return kp;
        }

        kp = (KeyPair) obj;
        if (!(kp.getPublic() instanceof JCERSAPublicKey) || !(kp.getPrivate() instanceof JCERSAPrivateCrtKey)) {
            errors.add(new ErrorEntry(ErrorType.UNREADABLE_KEY, "KeyPair object was not an RSA keyPair", true, null));
            kp = null;
            return kp;
        }
        return kp;
    }

    private static X509CertificateObject parseCert(String certIn, List<ErrorEntry> errors) {
        X509CertificateObject x509obj = null;
        List<PemBlock> blocks = PemUtils.parseMultiPem(certIn);
        Object obj;
        if (blocks.size() < 1) {
            errors.add(new ErrorEntry(ErrorType.UNREADABLE_CERT, "userCrt did not contain a pem block", true, null));
            return x509obj;
        }

        if (blocks.size() > 1) {
            errors.add(new ErrorEntry(ErrorType.UNREADABLE_CERT, "userCrt contains more then one pem block", true, null));
            return x509obj;
        }
        obj = blocks.get(0).getDecodedObject();
        if ((obj == null) || !(obj instanceof X509CertificateObject)) {
            errors.add(new ErrorEntry(ErrorType.UNREADABLE_CERT, "unable to parse userCrt to a X509Certificate", true, null));
            return x509obj;
        }
        x509obj = (X509CertificateObject) obj;
        return x509obj;
    }

    private static String invalidDateMessage(String premsg, Date dateEdge) {
        String edge = StaticHelpers.getDateString(dateEdge);
        String msg = String.format("%s %s", premsg, edge);
        return msg;
    }
}
