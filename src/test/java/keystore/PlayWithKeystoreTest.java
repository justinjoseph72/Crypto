package keystore;

import justin.app.digital_signature.keystore.PlayWithKeystore;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class PlayWithKeystoreTest {
    PlayWithKeystore playWithKeystore;

    @Before
    public void init(){
        playWithKeystore = new PlayWithKeystore();
    }

    @Test
    public void getPublicKeyFromKeyStore() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        playWithKeystore.getPrivateKeyFromKeyStore();
    }
}
