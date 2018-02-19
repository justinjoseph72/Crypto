package encryption;

import justin.app.encryption.AsymetricalKeyCreation;
import justin.app.encryption.AsymtericalEncryption;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

public class AsymetricalEncryptionTest {

    AsymetricalKeyCreation keyCreation;
    AsymtericalEncryption asymtericalEncryption;

    @Before
    public void init(){
        keyCreation = new AsymetricalKeyCreation();
        asymtericalEncryption = new AsymtericalEncryption();
    }

    @Test
    public void createRSAKeys() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        keyCreation.createKeyPair("RSA","private.key","public.key");
    }

    @Test
    public void createAESKeys()throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        keyCreation.createKeyPair("AES","privateAES.key","publicAES.key");
    }

    @Test
    public void getRSAKeys(){
        try {
            PublicKey publicKey = asymtericalEncryption.readPublicKeyfromFile("public.key");
            PrivateKey privateKey = asymtericalEncryption.readPrivateKeyFromFile("private.key");
            Assert.assertNotNull(publicKey);
            Assert.assertNotNull(privateKey);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testEncrypteDecrypt() throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        String data = " This is a data to encrypt";
        String encryptedData = asymtericalEncryption.rsaEncryptData(data);
        System.out.println(encryptedData);
        Assert.assertThat(data, Matchers.not(encryptedData));
        String decryptedData = asymtericalEncryption.rsaDecrypt(encryptedData);
        Assert.assertThat(decryptedData, Matchers.not(encryptedData));
        System.out.println(decryptedData);
        Assert.assertThat(decryptedData, Matchers.is(data));

    }
}
