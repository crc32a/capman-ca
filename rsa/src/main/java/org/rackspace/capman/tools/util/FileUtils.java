package org.rackspace.capman.tools.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FilenameFilter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.rackspace.capman.tools.ca.PemUtils;
import org.rackspace.capman.tools.ca.primitives.PemBlock;
import org.rackspace.capman.tools.util.exceptions.CapManUtilException;

public class FileUtils {

    private static final int BUFFSIZE = 64*1024;
    public static List<X509CertificateObject> readX509Dir(String dirName) throws CapManUtilException, FileNotFoundException, IOException {
        String fmt;
        String msg;
        List<X509CertificateObject> x509s = new ArrayList<X509CertificateObject>();
        File dirNameFile = new File(dirName);
        File[] files = dirNameFile.listFiles();
        if (files == null) {
            fmt = "\"%s\" is not a directory or is not a readable directory\n";
            msg = String.format(fmt, dirName);
            throw new CapManUtilException(msg);
        }
        for (int i = 0; i < files.length; i++) {
            File file = files[i];
            List<X509CertificateObject> readX509s = readX509File(file);
            x509s.addAll(readX509s);
        }
        return x509s;
    }

    public static List<X509CertificateObject> readX509File(String fileName) throws FileNotFoundException, IOException{
        File file = new File(fileName);
        List<X509CertificateObject> x509s = readX509File(file);
        return x509s;
    }

    public static List<X509CertificateObject> readX509File(File file) throws FileNotFoundException, IOException{
        List<X509CertificateObject> x509objs = new ArrayList<X509CertificateObject>();
        byte[] bytes = readFile(file);
        if (file.canRead() && file.isFile()) {
                List<PemBlock> pemBlocks;
                byte[] pemData = readFile(file);
                pemBlocks = PemUtils.parseMultiPem(pemData);
                for (PemBlock pemBlock : pemBlocks) {
                    if (pemBlock == null
                            || pemBlock.getDecodedObject() == null
                            || !(pemBlock.getDecodedObject() instanceof X509CertificateObject)) {
                        continue; // Skip null and Non x509 objects
                    }
                    x509objs.add((X509CertificateObject)pemBlock.getDecodedObject());
                }
            }
        return x509objs;
    }

    public static byte[] readFile(String fileName) throws FileNotFoundException, IOException{
        File file = new File(fileName);
        byte[] bytes = readFile(file);
        return bytes;
    }

    public static byte[] readFile(File file) throws FileNotFoundException, IOException {
        byte[] bytesOut;
        byte[] buff;
        int nbytes;
        FileInputStream is = new FileInputStream(file);
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        while (true) {
            buff = new byte[BUFFSIZE];
            nbytes = is.read(buff);
            if (nbytes < 0) {
                break;
            }
            os.write(buff);
        }
        bytesOut = os.toByteArray();
        is.close();
        os.close();
        return bytesOut;
    }
}
