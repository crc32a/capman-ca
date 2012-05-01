package org.rackspace.capman.tools.ca.primitives;

import java.util.Arrays;

public class PemBlock {

    private int lineNum;
    private byte[] pemData;
    private Object decodedObject;

    public PemBlock() {
        pemData = null;
        decodedObject = null;
    }

    public PemBlock(int lineNum, byte[] pemData, Object decodedObject) {
        int i;
        this.lineNum = lineNum;
        this.decodedObject = decodedObject;
        if (pemData == null) {
            this.pemData = null;
            return;
        }
        this.pemData = Arrays.copyOf(pemData, pemData.length);

    }

    public byte[] getPemData() {
        return pemData;
    }

    public void setPemData(byte[] pemData) {
        int i;
        if (pemData == null) {
            this.pemData = null;
        } else {
            this.pemData = Arrays.copyOf(pemData, pemData.length);
        }
    }

    public Object getDecodedObject() {
        return decodedObject;
    }

    public void setDecodedObject(Object decodedObject) {
        this.decodedObject = decodedObject;
    }

    public int getLineNum() {
        return lineNum;
    }

    public void setLineNum(int lineNum) {
        this.lineNum = lineNum;
    }
}
