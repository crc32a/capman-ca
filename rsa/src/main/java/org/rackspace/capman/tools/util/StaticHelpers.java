package org.rackspace.capman.tools.util;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;
import org.rackspace.capman.tools.ca.primitives.RsaConst;

public class StaticHelpers {

    private static final String[] int2hex;

    static {
        RsaConst.init();
        int2hex = new String[]{
                    "0", "1", "2", "3",
                    "4", "5", "6", "7",
                    "8", "9", "a", "b",
                    "c", "d", "e", "f"};

    }

    public static BigInteger string2BigInt(String in) throws UnsupportedEncodingException {
        byte[] strBytes = in.getBytes("UTF-8");
        return bytes2BigInt(strBytes);
    }

    public static BigInteger bytes2BigInt(byte[] in) {
        BigInteger out = BigInteger.ZERO;
        for (int i = 0; i < in.length; i++) {
            out = out.shiftLeft(8).add(BigInteger.valueOf(uint(in[i])));
        }
        return out;
    }

    public static String bytes2hex(byte[] in) {
        StringBuilder sb = new StringBuilder();
        if (in == null) {
            return null;
        }
        for (int i = 0; i < in.length; i++) {
            int byteInt = (in[i] >= 0) ? (int) in[i] : (int) in[i] + 256;
            sb.append(int2hex[byteInt >> 4]); // High nibble
            sb.append(int2hex[byteInt & 0x0f]); // Low nibble
        }
        String out = sb.toString();
        return out;
    }

    // Cause jython has a hard time building byte arrays
    public static byte[] string2bytes(String in) throws UnsupportedEncodingException {
        byte[] out = in.getBytes("UTF-8");
        return out;
    }

    private static int uint(byte in) {
        return (in >= 0) ? (int) in : (int) in + 256;
    }

    // Does nothing Useful. Just a doorstop for debuggin
    private int nop(int in) {
        byte inByte = (byte) (in % 256);
        int out = uint(inByte);
        return out;
    }

    // Cause I keep forget what an set operations really look like
    public static <U> Set<U> andSet(Set<U> a, Set<U> b) {
        Set<U> aCopy = new HashSet<U>(a);
        Set<U> bCopy = new HashSet<U>(b);
        aCopy.retainAll(bCopy);
        return aCopy;
    }

    public static <U> Set<U> orSet(Set<U> a, Set<U> b) {
        Set<U> aCopy = new HashSet<U>(a);
        Set<U> bCopy = new HashSet<U>(b);
        aCopy.addAll(bCopy);
        return aCopy;
    }

    // Also known as the asymetric difference of 2 sets
    public static <U> Set<U> subtractSet(Set<U> a, Set<U> b) {
        Set<U> aCopy = new HashSet<U>(a);
        Set<U> bCopy = new HashSet<U>(b);
        aCopy.removeAll(b);
        return aCopy;
    }

    // Also known as the symetric difference between sets
    public static <U> Set<U> xorSet(Set<U> a, Set<U> b) {
        Set<U> aCopy = new HashSet<U>(a);
        Set<U> bCopy = new HashSet<U>(b);

        Set<U> intersection = new HashSet<U>();
        Set<U> union = new HashSet<U>();
        intersection.addAll(aCopy);
        intersection.retainAll(bCopy);
        union.addAll(aCopy);
        union.addAll(bCopy);
        union.removeAll(intersection);
        return union;
    }
}
