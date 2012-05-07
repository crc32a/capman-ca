package org.rackspace.capman.tools.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.jce.provider.X509CertificateObject;

public class X509FileMap {
    private Map<String, X509CertificateObject> fileMap;

    public X509FileMap() {
        fileMap = new HashMap<String, X509CertificateObject>();
    }

    public void put(String filePath, X509CertificateObject crt) {
        fileMap.put(filePath,crt);
    }

    // O(1) hash search
    public X509CertificateObject get(String filePath){
        X509CertificateObject x509obj = fileMap.get(filePath);
        return x509obj;
    }

    // Linear O(n) search. for the reverse mapping
    public List<String> get(X509CertificateObject x509Obj){
        List<String> foundPaths = new ArrayList<String>();
        Set<String> mappedPaths = fileMap.keySet();
        for(String path : mappedPaths){
            X509CertificateObject currX509obj = fileMap.get(path);
            if(x509Obj.equals(currX509obj)) {
                foundPaths.add(path);
            }
        }
        return foundPaths;
    }

    public X509CertificateObject remove(String filePath){
        X509CertificateObject removedX509 = fileMap.remove(filePath);
        return removedX509;
    }

}
