package com.dawn.appkeystore;

import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.text.TextUtils;
import android.util.Base64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.security.auth.x500.X500Principal;

public class keyStoreUtils {
    private static volatile keyStoreUtils instance;
    private KeyStore keyStore;

    private keyStoreUtils() {
    }

    public static keyStoreUtils getInstance() {
        synchronized (keyStoreUtils.class) {
            if (null == instance) {
                instance = new keyStoreUtils();
            }
        }
        return instance;
    }

    public String decryptString(String needDecryptWord, String alias) {
        if (TextUtils.isEmpty(needDecryptWord) || TextUtils.isEmpty(alias)) {
            return "";
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
            initKeyStore(alias);
        }
        String decryptStr = "";

        try {
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);
            //RSAPrivateKey privateKey = (RSAPrivateKey) privateKeyEntry.getPrivateKey();

            //Cipher output = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
            Cipher output = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            //output.init(Cipher.DECRYPT_MODE, privateKey);
            output.init(Cipher.DECRYPT_MODE, privateKeyEntry.getPrivateKey());
            CipherInputStream cipherInputStream = new CipherInputStream(
                    new ByteArrayInputStream(Base64.decode(needDecryptWord, Base64.DEFAULT)), output);
            ArrayList<Byte> values = new ArrayList<>();
            int nextByte;
            while ((nextByte = cipherInputStream.read()) != -1) {
                values.add((byte)nextByte);
            }

            byte[] bytes = new byte[values.size()];
            for(int i = 0; i < bytes.length; i++) {
                bytes[i] = values.get(i).byteValue();
            }

            decryptStr = new String(bytes, 0, bytes.length, "UTF-8");

        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
        return decryptStr;
    }

    /**
     * 加密方法
     *
     * @param needEncryptWord 需要加密的字符串
     * @param alias           加密秘钥
     * @return
     */
    public String encryptString(String needEncryptWord, String alias) {
        if (TextUtils.isEmpty(needEncryptWord) || TextUtils.isEmpty(alias)) {
            return "";
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
            initKeyStore(alias);
        }
        String encryptStr = "";
        byte[] values = null;
        try {
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);

            Cipher inCipher;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                inCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
            } else {
                //若加密慢则改用上面的代码
                inCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            }
            inCipher.init(Cipher.ENCRYPT_MODE, privateKeyEntry.getCertificate().getPublicKey());

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, inCipher);
            cipherOutputStream.write(needEncryptWord.getBytes("UTF-8"));
            cipherOutputStream.close();
            values = outputStream.toByteArray();
            if(null != values){
                return Base64.encodeToString(values, Base64.DEFAULT);
            }else{
                return "";
            }
        } catch (Exception e) {
            return "";
        }

    }

    private void initKeyStore(String alias) {
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        createNewKeys(alias);
    }

    private void createNewKeys(String alias) {
        if (TextUtils.isEmpty(alias)) {
            return;
        }
        try {
            if (null != keyStore && keyStore.containsAlias(alias)) {
                Calendar start = Calendar.getInstance();
                Calendar end = Calendar.getInstance();
                end.add(Calendar.YEAR, 1);
                KeyPairGeneratorSpec spec = null;
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
                    spec = new KeyPairGeneratorSpec.Builder(MyApp.getApplication())
                            .setAlias(alias)
                            .setSubject(new X500Principal("CN=Sample Name, O=Android Authority"))
                            .setSerialNumber(BigInteger.ONE)
                            .setStartDate(start.getTime())
                            .setEndDate(end.getTime())
                            .build();

                    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
                    generator.initialize(spec);
                }

            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }
}
