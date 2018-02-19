package justin.app.digital_signature.keystore;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class PlayWithKeystore {
    public  void getPrivateKeyFromKeyStore() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStore ks = KeyStore.getInstance("JKS");
        FileInputStream ksfs = new FileInputStream("local-development-https.jks");
        BufferedInputStream bks = new BufferedInputStream(ksfs);
        ks.load(bks,"changeit".toCharArray());
        PrivateKey privateKey = (PrivateKey)ks.getKey("connections-dev","changeit".toCharArray());
        System.out.println(privateKey.getAlgorithm());
        Certificate certificate = ks.getCertificate("connections-dev");
        if(certificate!=null){
            byte[] encodedCertBytes = certificate.getEncoded();
            FileOutputStream certOs = new FileOutputStream("myCert");
            certOs.write(encodedCertBytes);
            certOs.close();
        }
    }
}
