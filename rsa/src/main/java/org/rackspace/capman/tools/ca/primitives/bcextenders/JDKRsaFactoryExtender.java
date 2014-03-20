

package org.rackspace.capman.tools.ca.primitives.bcextenders;

import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyFactorySpi;
import org.bouncycastle.jce.provider.JCERSAPublicKey;

public class JDKRsaFactoryExtender extends KeyFactorySpi{
    public JCERSAPublicKey getPublicKeyFromSpec(KeySpec ks) throws InvalidKeySpecException{
        PublicKey obj = engineGeneratePublic(ks);
        return (JCERSAPublicKey) engineGeneratePublic(ks);
    }

}
