package org.rackspace.capman.tools.ca.exceptions;

public class NullKeyException extends RsaException {
    public NullKeyException(){

    }
    public NullKeyException(String msg){
        super(msg);
    }
    public NullKeyException(Throwable th){
        super(th);
    }
    public NullKeyException(String msg,Throwable th){
        super(msg,th);
    }
}
