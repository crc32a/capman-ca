package org.rackspace.capman.tools.ca.primitives;

import org.rackspace.capman.tools.ca.StringUtils;

public class X509ExtContainer {

    private String oid;
    private boolean critical;
    private byte[] value;

    public X509ExtContainer(String oid, boolean isCritical, byte[] value) {
        this.oid = oid;
        this.critical = isCritical;
        this.value = value;
    }

    public X509ExtContainer() {
    }

    public String getOid() {
        return oid;
    }

    public void setOid(String oid) {
        this.oid = oid;
    }

    public byte[] getValue() {
        return value;
    }

    public void setValue(byte[] value) {
        this.value = value;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("{ oid=").append(oid).
                append(", isCritical=").
                append(critical).
                append(" value=").
                append(StringUtils.toHex(value)).
                append(" }");
        return sb.toString();
    }

    public boolean isCritical() {
        return critical;
    }

    public void setCritical(boolean critical) {
        this.critical = critical;
    }
}
