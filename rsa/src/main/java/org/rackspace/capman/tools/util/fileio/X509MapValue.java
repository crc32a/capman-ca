package org.rackspace.capman.tools.util.fileio;

import org.bouncycastle.jce.provider.X509CertificateObject;

public class X509MapValue {

    private X509CertificateObject x509CertificateObject;
    private String fileName;
    private int lineNum;

    public X509MapValue(X509CertificateObject x509CertificateObject, String fileName, int lineNum) {
        this.x509CertificateObject = x509CertificateObject;
        this.fileName = fileName;
        this.lineNum = lineNum;
    }

    public X509CertificateObject getX509CertificateObject() {
        return x509CertificateObject;
    }

    public String getFileName() {
        return fileName;
    }

    public int getLineNum() {
        return lineNum;
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = hash * 37 + this.x509CertificateObject.hashCode();
        hash = hash * 31 + this.fileName.hashCode();
        hash = hash * 47 + this.lineNum;
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (obj instanceof X509MapValue) {
            X509MapValue mapVal = (X509MapValue) obj;
            if (mapVal.getX509CertificateObject().equals(this.x509CertificateObject)
                    && mapVal.getFileName().equals(this.fileName)
                    && mapVal.getLineNum() == this.lineNum) {
                return true;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }

    @Override
    public String toString(){
        return String.format("%s[%d]",fileName,lineNum);
    }
}
