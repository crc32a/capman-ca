package org.rackspace.capman.tools.ca.zeus.primitives;

import java.util.List;
import org.rackspace.capman.tools.ca.primitives.RsaConst;
import org.rackspace.capman.tools.util.StaticHelpers;

public class ErrorEntry {

    private ErrorType errorType;
    private String errorDetail;
    private boolean fatal; // Is this an unignorable error
    private Throwable exception;

    public ErrorEntry(ErrorType errorType, String errorDetail, boolean recoverable, Throwable exception) {
        this.errorType = errorType;
        this.errorDetail = errorDetail;
        this.fatal = recoverable;
        this.exception = exception;
    }

    public ErrorType getErrorType() {
        return errorType;
    }

    public void setErrorType(ErrorType errorType) {
        this.errorType = errorType;
    }

    public String getErrorDetail() {
        return errorDetail;
    }

    public void setErrorDetail(String errorDetail) {
        this.errorDetail = errorDetail;
    }

    public boolean isFatal() {
        return fatal;
    }

    public void setFatal(boolean fatal) {
        this.fatal = fatal;
    }

    public Throwable getException() {
        return exception;
    }

    public void setException(Throwable exception) {
        this.exception = exception;
    }

    @Override
    public String toString() {
        return toString(false);
    }

    public String toString(boolean showException) {
        StringBuilder sb = new StringBuilder(RsaConst.PAGESIZE);
        sb.append(String.format("{%s,%s,", errorType.toString(), errorDetail));
        sb.append(fatal ? "Fatal" : "NotFatal}\n");
        if (!showException) {
            return sb.toString();
        }
        sb.append("Exceptions:\n");
        List<Throwable> exceptions = StaticHelpers.getExceptionCausesList(exception);
        for (Throwable ex : exceptions) {
            String exName = ex.getClass().getName();
            if (exName == null) {
                exName = "null";
            }
            String exMsg = ex.getMessage();
            if (exMsg == null) {
                exMsg = "null";
            }
            sb.append(String.format("%s:%s\n", exName, exMsg));
        }
        sb.append("}\n");
        return sb.toString();
    }
}
