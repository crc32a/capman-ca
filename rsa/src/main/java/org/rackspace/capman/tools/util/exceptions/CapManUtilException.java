package org.rackspace.capman.tools.util.exceptions;

public class CapManUtilException extends Exception{

    public CapManUtilException(Throwable cause) {
        super(cause);
    }

    public CapManUtilException(String message, Throwable cause) {
        super(message, cause);
    }

    public CapManUtilException(String message) {
        super(message);
    }

    public CapManUtilException() {
    }

}
