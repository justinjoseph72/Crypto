package justin.app.encryption;

import org.springframework.stereotype.Component;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

@Component
public class AsymetricalKeyCreation {

    public void createKeyPair(String algo,String privateKeyName,String publicKeyName) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algo);
        keyPairGenerator.initialize(2018);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        savePublicKey(keyPair,privateKeyName,publicKeyName);
    }

    private void savePublicKey(final KeyPair keyPair,String privateKeyName,String publicKeyName) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec publicKeySpec = factory.getKeySpec(keyPair.getPublic(),RSAPublicKeySpec.class);
        RSAPrivateKeySpec privateKeySpec = factory.getKeySpec(keyPair.getPrivate(),RSAPrivateKeySpec.class);
        saveToFile(publicKeyName,publicKeySpec.getModulus(),publicKeySpec.getPublicExponent());
        saveToFile(privateKeyName,privateKeySpec.getModulus(),privateKeySpec.getPrivateExponent());
    }

    private void saveToFile( String fileName, final BigInteger modulus, final BigInteger exponent) throws IOException {
        //fileName = "/keys/"+fileName;
        ObjectOutputStream oout = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileName)));
        try{
            oout.writeObject(modulus);
            oout.writeObject(exponent);
        }catch (Exception e){
            throw new IOException("Some error ",e);
        }finally {
            oout.close();
        }
    }


}
