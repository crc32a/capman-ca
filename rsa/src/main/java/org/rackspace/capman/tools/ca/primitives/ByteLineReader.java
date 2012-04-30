package org.rackspace.capman.tools.ca.primitives;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;

public class ByteLineReader {

    private static final byte CR = 13;
    private static final byte LF = 10;
    private static final int PAGESIZE = 4096;
    private ByteArrayInputStream inStream;

    public ByteLineReader(byte[] bytes) {
        inStream = new ByteArrayInputStream(bytes);
    }

    public int bytesAvailable() {
        return inStream.available();
    }

    public byte[] readLine(boolean chop) {
        ByteArrayOutputStream outStream = new ByteArrayOutputStream(PAGESIZE);
        while (inStream.available() > 0) {
            int ch = inStream.read();
            if (ch < 0) {
                break;
            }
            if (ch == CR) { // Skip Carriage Return Nonsense.
                continue;
            }
            if (ch == LF) {
                if (chop) {
                    break;
                } else {
                    outStream.write(ch);
                    break;
                }
            }
            outStream.write(ch);
        }
        byte[] line = outStream.toByteArray();
        return line;
    }

    public byte[] readLine() {
        return readLine(false);
    }

    public static boolean cmpBytes(byte[] a, byte[] b) {
        return Arrays.equals(a, b);
    }

    public static byte[] appendLF(byte[] bytesIn) {
        byte[] bytesOut = Arrays.copyOf(bytesIn,bytesIn.length + 1);
        bytesOut[bytesOut.length-1] = LF;
        return bytesOut;
    }

    public static byte[] copyBytes(byte[] inBytes) {
        byte[] outBytes = Arrays.copyOf(inBytes,inBytes.length);
        return outBytes;
    }


}
