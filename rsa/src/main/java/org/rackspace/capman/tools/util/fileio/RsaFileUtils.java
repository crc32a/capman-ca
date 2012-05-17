package org.rackspace.capman.tools.util.fileio;

import org.rackspace.capman.tools.util.X509MapValue;
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
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.rackspace.capman.tools.ca.PemUtils;
import org.rackspace.capman.tools.ca.primitives.PemBlock;
import org.rackspace.capman.tools.ca.primitives.RsaConst;
import org.rackspace.capman.tools.ca.exceptions.CapManUtilException;

public class RsaFileUtils {

    private static final int BUFFSIZE = 64 * 1024;

    static {
        RsaConst.init();
    }

    public static byte[] readFile(String fileName) throws FileNotFoundException, IOException {
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
            os.write(buff,0,nbytes);
        }
        bytesOut = os.toByteArray();
        is.close();
        os.close();
        return bytesOut;
    }

    // for jython
    public static List<File> dirWalk(String dirFileName, String patternString) {
        File dirFile = new File(dirFileName);
        Pattern p = (patternString == null) ? null : Pattern.compile(patternString);
        return dirWalk(dirFile, p);
    }

    // Warning Beware of dirwalk on directories containing directory links
    // A link such as "ln -s .. x" will cause circular walks. 
    public static List<File> dirWalk(File dirFile, Pattern fnPattern) {
        List<File> files = new ArrayList<File>();
        if (!dirFile.canRead() || !dirFile.isDirectory()) {
            return files;// Return empty list if directory is unreadable
        }
        File[] scanFiles = dirFile.listFiles();
        for (int i = 0; i < scanFiles.length; i++) {
            File curFile = scanFiles[i];
            String fullPath = curFile.getAbsolutePath();

            if (!curFile.canRead()) {
                continue; // Don't attempt to list unreadable files
            }
            if (curFile.isDirectory()) {
                files.addAll(dirWalk(curFile, fnPattern));
            }
            if (curFile.isFile()) {
                if (fnPattern != null) {
                    Matcher m = fnPattern.matcher(fullPath);
                    if (!m.matches()) { // If this didn't match the pattern re then skip it;
                        continue;
                    }
                }
                files.add(curFile);
            }
        }
        return files;
    }

    // For Jython
    public static List<X509MapValue> readX509File(String fileName) throws FileNotFoundException, IOException {
        File file = new File(fileName);
        return readX509FileToMapVals(file);
    }

    public static List<X509MapValue> readX509FileToMapVals(File file) throws FileNotFoundException, IOException {
        List<X509MapValue> valMapList = new ArrayList<X509MapValue>();
        byte[] pemBytes = readFile(file);
        List<PemBlock> blocks = PemUtils.parseMultiPem(pemBytes);
        for (PemBlock block : blocks) {
            Object decodedObj = block.getDecodedObject();
            if (decodedObj == null) {
                continue;
            }
            if (!(decodedObj instanceof X509CertificateObject)) {
                continue;
            }
            X509CertificateObject x509obj = (X509CertificateObject) block.getDecodedObject();
            X509MapValue valMap = new X509MapValue(x509obj, file.getAbsolutePath(), block.getLineNum());
            valMapList.add(valMap);
        }
        return valMapList;
    }

    public static List<X509MapValue> readX509FilesToMapVals(Collection<File> files) {
        List<X509MapValue> mapVals = new ArrayList<X509MapValue>();
        for (File file : files) {
            List<X509MapValue> fileMapVals;
            try {
                fileMapVals = readX509FileToMapVals(file);
            } catch (FileNotFoundException ex) {
                String msg = String.format("File not found %s SKIPPING x509 read\n", file.getAbsolutePath());
                Logger.getLogger(RsaFileUtils.class.getName()).log(Level.WARNING, msg, ex);
                continue;
            } catch (IOException ex) {
                Logger.getLogger(RsaFileUtils.class.getName()).log(Level.WARNING, null, ex);
                continue;
            }
            mapVals.addAll(fileMapVals);
        }
        return mapVals;
    }
}
