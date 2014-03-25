package org.rackspace.capman.tools.util;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.JCERSAPrivateCrtKey;
import org.bouncycastle.openssl.PEMKeyPair;
import org.rackspace.capman.tools.ca.PemUtils;
import org.rackspace.capman.tools.ca.exceptions.PemException;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;
import org.rackspace.capman.tools.ca.exceptions.PrivKeyDecodeException;
import org.rackspace.capman.tools.ca.primitives.RsaConst;
import org.rackspace.capman.tools.ca.exceptions.X509ReaderDecodeException;
import org.rackspace.capman.tools.ca.primitives.Debug;
import org.bouncycastle.jce.provider.HackedProviderAccessor;

public class PrivKeyReader {

    static {
        RsaConst.init();
    }
    private BigInteger N;
    private BigInteger P;
    private BigInteger Q;
    private BigInteger E;
    private BigInteger D;
    private BigInteger dP;
    private BigInteger dQ;
    private BigInteger QInv;

    public BigInteger getN() {
        return N;
    }

    public BigInteger getP() {
        return P;
    }

    public BigInteger getQ() {
        return Q;
    }

    public BigInteger getE() {
        return E;
    }

    public BigInteger getD() {
        return D;
    }

    public BigInteger getdP() {
        return dP;
    }

    public BigInteger getdQ() {
        return dQ;
    }

    public BigInteger getT() {
        return P.subtract(BigInteger.ONE).multiply(Q.subtract(BigInteger.ONE));
    }

    public JCERSAPrivateCrtKey getPrivKey() {
        return HackedProviderAccessor.newJCERSAPrivateCrtKey(this);
    }

    public static PrivKeyReader newPrivKeyReader(Object obj) throws PrivKeyDecodeException {
        String msg;
        if (obj instanceof String) {
            try {
                obj = PemUtils.fromPemString((String) obj);
                return newPrivKeyReader(obj);
            } catch (PemException ex) {
                throw new PrivKeyDecodeException("Error decoding Key", ex);
            }
        }
        if (obj instanceof PEMKeyPair) {
            PEMKeyPair pkp = (PEMKeyPair) obj;
            return newPrivKeyReader(pkp.getPrivateKeyInfo());
        }
        if (obj instanceof PrivateKeyInfo) {
            PrivateKeyInfo pkinfo = (PrivateKeyInfo) obj;
            Object pkfc;
            try {
                pkfc = PrivateKeyFactory.createKey(pkinfo);
            } catch (IOException ex) {
                msg = String.format("Error decoding Private key from class %s", pkinfo.getClass().getName());
                throw new PrivKeyDecodeException(msg);
            }
            return newPrivKeyReader(pkfc);
        }
        if (obj instanceof RSAPrivateCrtKeyParameters) {
            RSAPrivateCrtKeyParameters rckp = (RSAPrivateCrtKeyParameters) obj;
            PrivKeyReader pr = new PrivKeyReader();
            pr.setN(rckp.getModulus());
            pr.setP(rckp.getP());
            pr.setQ(rckp.getQ());
            pr.setD(rckp.getExponent());
            pr.setE(rckp.getPublicExponent());
            pr.setdP(rckp.getDP());
            pr.setdQ(rckp.getDQ());
            pr.setQInv(rckp.getQInv());
            return pr;
        }
        if (obj instanceof PEMKeyPair) {
            PEMKeyPair pkp = (PEMKeyPair) obj;
            try {
                Object pkfc = PrivateKeyFactory.createKey(pkp.getPrivateKeyInfo());
                RSAPrivateCrtKeyParameters params = (RSAPrivateCrtKeyParameters) pkfc;
                return newPrivKeyReader(params);
            } catch (IOException ex) {
                throw new PrivKeyDecodeException("Error decoding RSAPrivateCrtKeyParameters from PrivateKeyInfo");
            }

        }
        msg = String.format("Error don't know how to convert class %s to privKeyReader", obj.getClass().getName());
        throw new PrivKeyDecodeException(msg);
    }

    public KeyPair toKeyPair() throws InvalidKeySpecException {
        //KeyPair kp = HackedProviderAccessor.newKeyPair(privKey);
        KeyPair kp = null;
        return kp;
    }

    public static String getPubKeyHash(PublicKey pubKey) {
        SubjectKeyIdentifierStructure skis;
        try {
            skis = new SubjectKeyIdentifierStructure(pubKey);
        } catch (InvalidKeyException ex) {
            return null;
        }
        byte[] keyIdBytes = skis.getKeyIdentifier();
        if (keyIdBytes == null) {
            return null;
        }
        String out = StaticHelpers.bytes2hex(keyIdBytes);
        return out;

    }

    public void setP(BigInteger P) {
        this.P = P;
    }

    public void setQ(BigInteger Q) {
        this.Q = Q;
    }

    public void setE(BigInteger E) {
        this.E = E;
    }

    public void setD(BigInteger D) {
        this.D = D;
    }

    public void setdP(BigInteger dP) {
        this.dP = dP;
    }

    public void setdQ(BigInteger dQ) {
        this.dQ = dQ;
    }

    public void setN(BigInteger N) {
        this.N = N;
    }

    public BigInteger getQInv() {
        return QInv;
    }

    public void setQInv(BigInteger QInv) {
        this.QInv = QInv;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("N=").append(N.toString()).append("\n").
                append("P=").append(P.toString()).append("\n").
                append("Q=").append(Q.toString()).append("\n").
                append("E=").append(E.toString()).append("\n").
                append("D=").append(D.toString()).append("\n").
                append("dP=").append(dP.toString()).append("\n").
                append("dQ=").append(dQ.toString()).append("\n").
                append("QInv=").append(QInv.toString()).append("\n");
        return sb.toString();
    }
}
