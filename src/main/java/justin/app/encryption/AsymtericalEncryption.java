package justin.app.encryption;

import org.springframework.stereotype.Component;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

@Component
public class AsymtericalEncryption {

    public PublicKey readPublicKeyfromFile(String keyFileName) throws IOException {
            ObjectInputStream oos = new ObjectInputStream(new BufferedInputStream(new FileInputStream(keyFileName)));
            try{
                BigInteger modulus = (BigInteger)oos.readObject();
                BigInteger exponenet = (BigInteger)oos.readObject();
                RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus,exponenet);
                KeyFactory factory = KeyFactory.getInstance("RSA");
                PublicKey publicKey = factory.generatePublic(keySpec);
                return publicKey;
            }catch (Exception e){
                throw new IOException(e);
            }
            finally {
                oos.close();
            }

    }

    public PrivateKey readPrivateKeyFromFile(String keyFileName) throws IOException {
        ObjectInputStream oos = new ObjectInputStream(new BufferedInputStream(new FileInputStream(keyFileName)));
        try{
            BigInteger modulus = (BigInteger)oos.readObject();
            BigInteger exponenet = (BigInteger)oos.readObject();
            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(modulus,exponenet);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = factory.generatePrivate(keySpec);
            return privateKey;
        }catch (Exception e){
            throw new IOException(e);
        }
        finally {
            oos.close();
        }
    }

    public String rsaEncryptData(String data) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] dataByte = data.getBytes();
        PublicKey publicKey = readPublicKeyfromFile("public.key");
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE,publicKey);
        byte[] encryptedData = cipher.doFinal(dataByte);
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    public String rsaDecrypt(String encryptedData) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] decodedEncryptedDataByte = Base64.getDecoder().decode(encryptedData);
        PrivateKey privateKey = readPrivateKeyFromFile("private.key");
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE,privateKey);
        byte[] decryptedByte = cipher.doFinal(decodedEncryptedDataByte);
        return new String(decryptedByte);
    }

}
