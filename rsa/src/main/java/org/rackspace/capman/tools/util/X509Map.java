package org.rackspace.capman.tools.util;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.jce.provider.X509CertificateObject;

public class X509Map {

    private Set<X509MapValue> mapValSet;
    private Map<String, Set<X509MapValue>> fileMap;
    private Map<X509CertificateObject, Set<X509MapValue>> x509Map;

    public X509Map() {
        mapValSet = new HashSet<X509MapValue>();
        fileMap = new HashMap<String, Set<X509MapValue>>();
        x509Map = new HashMap<X509CertificateObject, Set<X509MapValue>>();
    }

    public X509Map(Collection<X509MapValue> map) {
        mapValSet = new HashSet<X509MapValue>();
        fileMap = new HashMap<String, Set<X509MapValue>>();
        x509Map = new HashMap<X509CertificateObject, Set<X509MapValue>>();
        for (X509MapValue mapVal : map) {
            if (!fileMap.containsKey(mapVal.getFileName())) {
                fileMap.put(mapVal.getFileName(), new HashSet<X509MapValue>());
            }
            if (!x509Map.containsKey(mapVal.getX509CertificateObject())) {
                x509Map.put(mapVal.getX509CertificateObject(), new HashSet<X509MapValue>());
            }
            mapValSet.add(mapVal);
            fileMap.get(mapVal.getFileName()).add(mapVal);
            x509Map.get(mapVal.getX509CertificateObject()).add(mapVal);
        }
    }

    public void clear() {
        mapValSet = new HashSet<X509MapValue>();
        fileMap = new HashMap<String, Set<X509MapValue>>();
        x509Map = new HashMap<X509CertificateObject, Set<X509MapValue>>();
    }

    public void putAll(Collection<X509MapValue> mapVals) {
        for (X509MapValue mapVal : mapVals) {
            put(mapVal);
        }
    }

    public void put(X509MapValue mapVal) {
        mapValSet.add(mapVal);
        if (!fileMap.containsKey(mapVal.getFileName())) {
            fileMap.put(mapVal.getFileName(), new HashSet<X509MapValue>());
        }
        if (!x509Map.containsKey(mapVal.getX509CertificateObject())) {
            x509Map.put(mapVal.getX509CertificateObject(), new HashSet<X509MapValue>());
        }
        fileMap.get(mapVal.getFileName()).add(mapVal);
        x509Map.get(mapVal.getX509CertificateObject()).add(mapVal);
    }

    public Set<String> fileKeys() {
        return fileMap.keySet();
    }

    public Set<X509CertificateObject> x509CertificateObjectKeys() {
        return x509Map.keySet();
    }

    public Set<X509MapValue> fromFile(String fileName) {
        Set<X509MapValue> resultSet = fileMap.get(fileName);
        if (resultSet == null) {
            return new HashSet<X509MapValue>(); // Its impolite to return null when an Empty list is better
        }
        return resultSet;
    }

    public Set<X509MapValue> fromX509CertificateObject(X509CertificateObject x509obj) {
        Set<X509MapValue> resultSet = x509Map.get(x509obj);
        if (resultSet == null) {
            return new HashSet<X509MapValue>(); // See above comment
        }
        return resultSet;
    }

    public Set<X509MapValue> values() {
        return new HashSet<X509MapValue>(mapValSet);
    }
}