package org.rackspace.capman.tools.util;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class StaticHelpers {

    public static String int2hex[] = new String[]{
        "0", "1", "2", "3",
        "4", "5", "6", "7",
        "8", "9", "a", "b",
        "c", "d", "e", "f"};

    public static BigInteger string2BigInt(String in) throws UnsupportedEncodingException {
        byte[] strBytes = in.getBytes("UTF-8");
        return bytes2BigInt(strBytes);
    }

    public static BigInteger bytes2BigInt(byte[] in) {
        BigInteger out = BigInteger.ZERO;
        for (int i = 0; i < in.length; i++) {
            BigInteger bv = BigInteger.valueOf(uint(in[i]));
            out = out.shiftLeft(8);
            out = out.add(bv);
        }
        return out;
    }

    public static String bytes2hex(byte[] in){
        StringBuilder sb = new StringBuilder();
        for(int i=0;i<in.length;i++){
            int byteInt = (in[i] >= 0) ? (int) in[i] : (int) in[i] + 256;
            sb.append(int2hex[byteInt>>4]); // High nibble
            sb.append(int2hex[byteInt&0x0f]); // Low nibble
        }
        String out = sb.toString();
        return out;
    }

    // Cause jython has a hard time building byte arrays
    public static  byte[] string2bytes(String in) throws UnsupportedEncodingException{
    	byte[] out = in.getBytes("UTF-8");
        return out;
    }
    
    private static int uint(byte in) {
        return (in >= 0) ? (int) in : (int) in + 256;
    }

    // Does nothing Useful. Just a doorstop for debuggin
    private int nop(int in) {
        byte inByte = (byte)(in%256);
        int out = uint(inByte);
        return out;
    }
}
