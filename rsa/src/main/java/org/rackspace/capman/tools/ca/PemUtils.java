package org.rackspace.capman.tools.ca;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PEMWriter;
import org.rackspace.capman.tools.ca.primitives.RsaConst;
import org.rackspace.capman.tools.ca.primitives.PemBlock;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.security.Provider;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.rackspace.capman.tools.ca.exceptions.PemException;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.nio.charset.Charset;
import org.rackspace.capman.tools.ca.primitives.ByteLineReader;
import static org.rackspace.capman.tools.ca.primitives.ByteLineReader.cmpBytes;
import static org.rackspace.capman.tools.ca.primitives.ByteLineReader.appendLF;

public class PemUtils {

    private static final byte[] BEG_PRV;
    private static final byte[] END_PRV;
    private static final byte[] BEG_CSR;
    private static final byte[] END_CSR;
    private static final byte[] BEG_CRT;
    private static final byte[] END_CRT;
    private static final int CR = 13;
    private static final int LF = 10;
    private static final int PAGESIZE = 4096;

    static {
        BEG_PRV = StringUtils.asciiBytes("-----BEGIN RSA PRIVATE KEY-----");
        END_PRV = StringUtils.asciiBytes("-----END RSA PRIVATE KEY-----");
        BEG_CSR = StringUtils.asciiBytes("-----BEGIN CERTIFICATE REQUEST-----");
        END_CSR = StringUtils.asciiBytes("-----END CERTIFICATE REQUEST-----");
        BEG_CRT = StringUtils.asciiBytes("-----BEGIN CERTIFICATE-----");
        END_CRT = StringUtils.asciiBytes("-----END CERTIFICATE-----");
    }

    public static byte[] readFileToByteArray(String fileName) throws FileNotFoundException, IOException {
        byte[] data;
        String fmt;
        String msg;
        FileInputStream fis;
        InputStreamReader isr;
        File file;
        file = new File(fileName);
        long flen = file.length();
        if (flen > Integer.MAX_VALUE) {
            fmt = "can not read more then %d bytes\n";
            msg = String.format(fmt, Integer.MAX_VALUE);
            throw new IOException(msg);
        }
        fis = new FileInputStream(file);
        data = new byte[(int) flen];
        fis.read(data, 0, (int) flen);
        fis.close();
        return data;
    }

    public static void writeFileFromByteArray(String fileName, byte[] data) throws IOException {
        File file;
        FileOutputStream fs;
        DataOutputStream ds;
        file = new File(fileName);
        fs = new FileOutputStream(file);
        ds = new DataOutputStream(fs);
        ds.write(data);
        ds.flush();
        ds.close();
    }

    public static Object fromPemString(String pem) throws PemException {
        try {
            byte[] pemBytes = pem.getBytes("US-ASCII");
            return fromPem(pemBytes);
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(PemUtils.class.getName()).log(Level.SEVERE, null, ex);
            throw new PemException("Error decodeing PEM", ex);
        }
    }

    public static Object fromPem(byte[] pem) throws PemException {
        Object out = null;
        ByteArrayInputStream bas;
        InputStreamReader isr;
        PEMReader pr;

        bas = new ByteArrayInputStream(pem);
        isr = new InputStreamReader(bas);
        pr = new PEMReader(isr);
        try {
            out = pr.readObject();
            pr.close();
        } catch (IOException ex) {
            throw new PemException("Could not read PEM data", ex);
        }
        return out;
    }

    public static String toPemString(Object obj) throws PemException {
        byte[] pemBytes = toPem(obj);
        String out;
        try {
            out = new String(pemBytes, "US-ASCII");
        } catch (UnsupportedEncodingException ex) {
            throw new PemException("Could not encode Object to PEM", ex);
        }
        return out;

    }

    public static byte[] toPem(Object obj) throws PemException {
        byte[] out;
        ByteArrayOutputStream bas;
        OutputStreamWriter osw;
        PEMWriter pw;
        bas = new ByteArrayOutputStream(RsaConst.PAGESIZE);
        osw = new OutputStreamWriter(bas);
        pw = new PEMWriter(osw);
        try {
            pw.writeObject(obj);
            pw.flush();
            pw.close();
        } catch (IOException ex) {
            throw new PemException("Error encoding object to PEM", ex);
        }
        out = bas.toByteArray();
        return out;
    }

    public static List<PemBlock> parseMultiPem(byte[] multiPemBytes) {
        String lineDBG="";
        String multiPemString = "";
        List<PemBlock> pemBlocks = new ArrayList<PemBlock>();
        ByteLineReader br = new ByteLineReader(multiPemBytes);
        boolean outsideBlock = true;
        int lc = 1;
        ByteArrayOutputStream bos;
        PemBlock pemBlock = null;
        bos = null;
        Object decodedObject = null;
        try {
            multiPemString = new String(multiPemBytes, "US-ASCII");
        } catch (UnsupportedEncodingException ex) {
            multiPemString = "You got to be kidding me";
        }
        while (br.bytesAvailable() > 0) {
            byte[] line = br.readLine(true);
            lc++;
            if (isEmptyLine(line)) {
                continue;
            }
            try {
                lineDBG = new String(line, "US-ASCII");
            } catch (UnsupportedEncodingException ex) {
                lineDBG = "EXCEPTION";
            }
            if (outsideBlock) {
                if (isBegPemBlock(line)) {
                    bos = new ByteArrayOutputStream(PAGESIZE);
                    pemBlock = new PemBlock();
                    pemBlock.setLineNum(lc);
                    pemBlock.setDecodedObject(null);
                    pemBlock.setPemData(null);
                    writeLine(bos,line);
                    outsideBlock = !outsideBlock;
                    continue;
                } else {
                    continue; // We are still outside the a block so skip this line
                }
            } else {
                // We are inside a pemBlock
                if (isEndPemBlock(line)) {
                    outsideBlock = !outsideBlock;
                    writeLine(bos, line);
                    byte[] bytes = bos.toByteArray();
                    pemBlock.setPemData(bytes);
                    try {
                        decodedObject = PemUtils.fromPem(bytes);
                    } catch (PemException ex) {
                        decodedObject = null;
                    }
                    pemBlock.setDecodedObject(decodedObject);
                    pemBlocks.add(pemBlock);
                } else {
                    writeLine(bos, line);
                }
            }
        }
        return pemBlocks;
    }

    public static void writeLine(ByteArrayOutputStream bos, byte[] line) {
        for (int i = 0; i < line.length; i++) {
            int byteInt = (line[i] >= 0) ? (int) line[i] : (int) line[i] + 256;
            bos.write(byteInt); // Not sure why single byte writes are Exception free. Its annoying.
        }
        // attach LF
        bos.write(LF);

    }

    public static boolean isBegPemBlock(byte[] line) {
        if (cmpBytes(line, BEG_PRV)) {
            return true;
        }
        if (cmpBytes(line, BEG_CSR)) {
            return true;
        }
        if (cmpBytes(line, BEG_CRT)) {
            return true;
        }
        return false;
    }

    public static boolean isEndPemBlock(byte[] line) {
        if (cmpBytes(line, END_PRV)) {
            return true;
        }
        if (cmpBytes(line, END_CSR)) {
            return true;
        }
        if (cmpBytes(line, END_CRT)) {
            return true;
        }
        return false;
    }

    public static boolean isEmptyLine(byte[] line) {
        if (line.length <= 0) {
            return true;
        } else {
            return false;
        }
    }
}
