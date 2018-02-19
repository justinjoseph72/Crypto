package encryption;

import justin.app.encryption.SymtericalEncryption;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class SymetricalEncryptionTest {

    private SymtericalEncryption symtericalEncryption;

    @Before
    public void init(){
        symtericalEncryption = new SymtericalEncryption();
    }

    @Test
    public void testEncryptionAndDecryptions() throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        String key = "JustinRobinSaumy";
        String data =" I am learning Symtercial Encryption";
        String iv =  "JustinRobinSaumy";

        String encryptedData = symtericalEncryption.encrpytData(key,data,iv);
        System.out.println(encryptedData);
        Assert.assertThat(data,Matchers.not(encryptedData));
        String decryptedDAta = symtericalEncryption.decryptData(key,encryptedData,iv);
        Assert.assertThat(decryptedDAta,Matchers.not(encryptedData));
        Assert.assertThat(decryptedDAta,Matchers.is(data));

    }

    @Test
    public void testbase64Encoding(){
        symtericalEncryption.testBaseencoing("ssss");
    }

}
