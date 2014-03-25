package org.bouncycastle.jce.provider;

import java.math.BigInteger;
import java.security.spec.InvalidKeySpecException;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jce.provider.JCERSAPrivateCrtKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyPair;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jce.provider.JCERSAPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyFactorySpi;
import org.rackspace.capman.tools.ca.primitives.bcextenders.JDKRsaFactoryExtender;
import org.rackspace.capman.tools.util.PrivKeyReader;

public class HackedProviderAccessor {

    public static KeyPair newKeyPair(JCERSAPrivateCrtKey jrpck) throws InvalidKeySpecException {
        PrivateKey privKey = (PrivateKey) jrpck;
        PublicKey pubKey = newJCERSAPublicKey(jrpck);
        KeyPair kp = new KeyPair(pubKey, privKey);
        return kp;
    }

    public static JCERSAPrivateCrtKey newJCERSAPrivateCrtKey(PrivKeyReader r){
        RSAPrivateCrtKeyParameters p = new RSAPrivateCrtKeyParameters(r.getN(),r.getE(),r.getD(),r.getP(),r.getQ(),r.getdP(),r.getdQ(),r.getQInv());
        return new JCERSAPrivateCrtKey(p);
    }

    public static RSAKeyParameters newRSAKeyParameters(JCERSAPublicKey jPub) {
        RSAKeyParameters pub;

        BigInteger n = jPub.getModulus();
        BigInteger e = jPub.getPublicExponent();
        boolean isPrivate = false;

        pub = new RSAKeyParameters(isPrivate, n, e);
        return pub;
    }

    public static JCERSAPublicKey newJCERSAPublicKey(JCERSAPrivateCrtKey privKey) throws InvalidKeySpecException {
        BigInteger mod = privKey.getModulus();
        BigInteger pubExp = privKey.getPublicExponent();
        RSAPublicKeySpec rsaPubKeySpec = new RSAPublicKeySpec(mod, pubExp);
        JDKRsaFactoryExtender rsaFactory = new JDKRsaFactoryExtender();
        KeyFactorySpi wtf = new KeyFactorySpi();
        JCERSAPublicKey publicKey = (JCERSAPublicKey) rsaFactory.getPublicKeyFromSpec(rsaPubKeySpec);
        return publicKey;
    }
}
