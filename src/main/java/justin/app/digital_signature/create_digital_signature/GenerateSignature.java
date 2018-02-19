package justin.app.digital_signature.create_digital_signature;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;

public class GenerateSignature {

    public static void main(String... args) {
        if (args.length != 1) {
            System.out.println("Usage: GenSig nameOfFileToSign");
        } else try {
            //creating an instance of the KeyPairGenerator with a DSA algorithm
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
           /* to initalize the keyGen we need a key length and an instance of SecureRandom with an
            algorithm and provider
            */
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG", "SUN");
            keyGen.initialize(1024, secureRandom);
            //generating the keypairs
            KeyPair pair = keyGen.generateKeyPair();
            PrivateKey privateKey = pair.getPrivate();
            PublicKey pub = pair.getPublic();
            //saving public key
            saveEncodedPublicKey(pub);
            System.out.println("Saved the public key");
            // Creating signature object
            Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
            //initalizing signature object
            dsa.initSign(privateKey);
            byte[] realSign = signData(args[0], dsa);
            //saving the signed document
            saveSignedFile(realSign);
            System.out.println("Saved the signed data");

        } catch (Exception e) {
            System.err.println("Caught Exception " + e.toString());
        }
    }

    private static byte[] signData(String filePath, Signature dsa) throws IOException, SignatureException {
        FileInputStream fis = new FileInputStream(filePath);
        BufferedInputStream bufin = new BufferedInputStream(fis);
        byte[] buffer = new byte[1024];
        int len;
        while ((len = bufin.read(buffer)) >= 0) {
            dsa.update(buffer, 0, len);
        }
        ;
        bufin.close();
        byte[] realSig = dsa.sign();
        return realSig;
    }

    private static void saveSignedFile(byte[] realSign) throws IOException {
        FileOutputStream signFos = new FileOutputStream("sign");
        signFos.write(realSign);
        signFos.close();
    }

    private static void saveEncodedPublicKey(PublicKey pub) throws IOException {
        byte[] key = pub.getEncoded();
        FileOutputStream fosStream = new FileOutputStream("suepk");
        fosStream.write(key);
        fosStream.close();
    }


}
