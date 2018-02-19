package justin.app.encryption;

import org.springframework.stereotype.Component;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

@Component
public class SymtericalEncryption {

    private static String ALGORITHM ="AES";

    public String encrpytData(String key, String data,String iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {

        byte[] keyBytes = key.getBytes();
        byte[] dataBytes = data.getBytes();
        byte[] ivBytes = iv.getBytes();

        // using the AES algorithn to encrypt
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes,ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE,keySpec, new IvParameterSpec(ivBytes));
        byte[] encryptedDataByte = cipher.doFinal(dataBytes);
        return Base64.getEncoder().encodeToString(encryptedDataByte);
    }

    public String decryptData(String key, String data,String iv) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        byte[] keyBytes = key.getBytes();
        byte[] dataBytes = Base64.getDecoder().decode(data);
        byte[] ivBytes = iv.getBytes();

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes,ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE,keySpec,new IvParameterSpec(ivBytes));
        byte[] decryptedDataByte = cipher.doFinal(dataBytes);
        String decryptedData = new String(decryptedDataByte);
        return decryptedData;
    }

    public void testBaseencoing(String data){
        System.out.println(Base64.getEncoder().encodeToString(data.getBytes()));
    }
}
