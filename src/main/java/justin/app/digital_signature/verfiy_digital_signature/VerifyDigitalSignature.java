package justin.app.digital_signature.verfiy_digital_signature;

import javax.swing.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.*;

public class VerifyDigitalSignature {

    public static void main(String... args) {
        if (args.length != 3) {
            System.out.println("Usage: Verifysignature " +
                    "publickeyfile signaturefile datafile");
        } else try {
            //getting the encoded public key bytes
            byte[] encodeKey = getBytesFromFile(args[0]);
            //getting the encoder
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encodeKey);
            KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
            PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);
            //get signature byte
            byte[] signToVerify = getBytesFromFile(args[1]);
            //creating a signature instance
            Signature sig = Signature.getInstance("SHA1withDSA", "SUN");
            //initalize the signature object for verification
            sig.initVerify(publicKey);
            updateDataWithSignature(sig, args[2]);
            //verify the signature
            boolean verify = sig.verify(signToVerify);
            System.out.println(" signature verifies : " + verify);
        } catch (Exception e) {
            System.err.println("Caught Exception " + e.toString());
        }
    }

    private static byte[] getBytesFromFile(String publicKeyPath) throws IOException {
        FileInputStream keyStream = new FileInputStream(publicKeyPath);
        byte[] encodeKey = new byte[keyStream.available()];
        keyStream.read(encodeKey);
        keyStream.close();
        return encodeKey;
    }

    public static void updateDataWithSignature(Signature sig, String pathToFile) throws IOException, SignatureException {
        FileInputStream dataFis = new FileInputStream(pathToFile);
        BufferedInputStream bufin = new BufferedInputStream(dataFis);
        int len;
        byte[] buffer = new byte[1024];
        while (bufin.available() != 0) {
            len = bufin.read(buffer);
            sig.update(buffer, 0, len);
        }
        bufin.close();
    }




}
