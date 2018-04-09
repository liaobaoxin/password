package com.lbx.password;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * @Author:
 * @date 2018/4/9 8:29
 */
public class Cryptology {

    public static final String KEY_ALGORITHM = "RSA";
    public static final String CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";
    public static final String PUBLIC_KEY = "publicKey";
    public static final String PRIVATE_KEY = "privateKey";
    public static final Integer KEY_SIZE = 1024;

    public static void main(String[] args) throws Exception {
        //原文
        String txt = "abc";
        System.out.println("需要加密的原始数据"+txt);

        System.out.println();

        //获得密钥对Map
        Map<String, byte[]> keyMap = getKeyMap();
        //获得公钥
        String publicKeyStr = encryptBASE64(keyMap.get(PUBLIC_KEY));
        System.out.println("公钥\n\r"+publicKeyStr);

        //获得密钥
        String privateKeyStr = encryptBASE64(keyMap.get(PRIVATE_KEY));
        System.out.println("私钥\n\r"+privateKeyStr);

        //将私钥规范
        PrivateKey privateKey = restorePrivateKey(decryptBASE64(privateKeyStr));

        //将原文更利于私钥加密
        byte[] encodedText = RSAEncode(privateKey, txt.getBytes("UTF-8"));

        //私钥加密后的数据
        String privateResult = byteArrayToHexString(encodedText);
        System.out.println("加密后的256位数据\n\r"+privateResult);
        
        PublicKey publicKey = restorePublicKey(decryptBASE64(publicKeyStr));
        // 公钥解密
        System.out.println("公钥解密: " + RSADecode(publicKey, hexStringToByte(privateResult)));
    }

    /**
     * 生成密钥对。注意这里是生成密钥对KeyMap，再由密钥对获取公私钥  方法每运行一次获得一对不同的公钥私钥。
     *
     * @return
     */
    public static Map<String, byte[]> getKeyMap() {
        try {
            //返回生成指定算法的 public/private 密钥对的 KeyPairGenerator 对象。 参数RSA算法
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
            //初始化RSA长度，RSA密钥长度必须是64的倍数，在512~65536之间。默认是1024
            keyPairGenerator.initialize(KEY_SIZE);
            //生成一个密钥对
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            //获得公钥
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            //获得私钥
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

            Map<String, byte[]> keyMap = new HashMap<String, byte[]>(2);
            //可以通过getEncoded()方法获取返回类型为byte[]的数组
            keyMap.put(PUBLIC_KEY, publicKey.getEncoded());

            keyMap.put(PRIVATE_KEY, privateKey.getEncoded());
            return keyMap;
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }


    }

    /**
     * 公钥，X509EncodedKeySpec 用于构建公钥的规范
     *
     * @param keyBytes
     * @return
     */
    public static PublicKey restorePublicKey(byte[] keyBytes) {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);

        try {
            KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM);
            PublicKey publicKey = factory.generatePublic(x509EncodedKeySpec);
            return publicKey;
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 私钥，PKCS8EncodedKeySpec 用于构建私钥的规范
     *
     * @param keyBytes
     * @return
     */
    public static PrivateKey restorePrivateKey(byte[] keyBytes) {

        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
                keyBytes);

        KeyFactory factory;
        try {
            factory = KeyFactory.getInstance(KEY_ALGORITHM);
            PrivateKey privateKey = factory
                    .generatePrivate(pkcs8EncodedKeySpec);
            return privateKey;
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }


        return null;
    }

    /**
     * 加密
     *
     * @param key
     * @param plainText
     * @return
     */
    public static byte[] RSAEncode(PrivateKey key, byte[] plainText) {

        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(plainText);
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (BadPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;

    }

    /**
     * 解密
     *
     * @param key
     * @param encodedText
     * @return
     */
    public static String RSADecode(PublicKey key, byte[] encodedText) {

        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);
            return new String(cipher.doFinal(encodedText));
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (BadPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;

    }

    /**
     * 将String转换为字节数组
     **/
    public static byte[] decryptBASE64(String key) throws Exception {
        return (new BASE64Decoder()).decodeBuffer(key);
    }

    /**
     * 将字节数组转换为String
     **/
    public static String encryptBASE64(byte[] key) throws Exception {

        return (new BASE64Encoder()).encodeBuffer(key);
    }

    // 将字节转换为十六进制字符串
    private static String byteToHexString(byte ib) {
        char[] Digit = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A',
                'B', 'C', 'D', 'E', 'F'};
        char[] ob = new char[2];
        ob[0] = Digit[(ib >>> 4) & 0X0F];
        ob[1] = Digit[ib & 0X0F];
        String s = new String(ob);
        return s;
    }

    // 将字节数组转换为十六进制字符串
    private static String byteArrayToHexString(byte[] bytearray) {
        String strDigest = "";
        for (int i = 0; i < bytearray.length; i++) {
            strDigest += byteToHexString(bytearray[i]);
        }
        return strDigest;
    }

    //16进制字符串转为字节数组
    public static byte[] hexStringToByte(String hex) {
        int len = (hex.length() / 2);
        byte[] result = new byte[len];
        char[] achar = hex.toCharArray();
        for (int i = 0; i < len; i++) {
            int pos = i * 2;
            result[i] = (byte) (toByte(achar[pos]) << 4 | toByte(achar[pos + 1]));
        }

        return result;
    }

    public static int toByte(char c) {
        byte b = (byte) "0123456789ABCDEF".indexOf(c);
        return b;
    }
}
