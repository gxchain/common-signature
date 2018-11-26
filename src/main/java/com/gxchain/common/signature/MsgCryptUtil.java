package com.gxchain.common.signature;

import com.google.common.base.Preconditions;
import com.google.common.primitives.Bytes;
import com.gxchain.common.signature.utils.*;
import org.apache.commons.lang3.RandomStringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * @Description
 * @Author Hanawa
 * @Date 2018/4/12
 * @Version 1.0
 */
public class MsgCryptUtil {
    private static final Logger LOGGER = LoggerFactory.getLogger(MsgCryptUtil.class);

    /**
     * 数据加密
     *
     * @param priKey  私钥
     * @param pubKey  公钥
     * @param nonce   大整数
     * @param message 消息明文
     * @return
     */
    public static String encrypt(String priKey, String pubKey, Long nonce, String message) {
        return Util.bytesToHex(encryptMessage(new Wif(priKey).getPrivateKey(), new Address(pubKey).getPublicKey(), BigInteger.valueOf(nonce), message));
    }

    /**
     * 数据解密
     *
     * @param priKey    私钥
     * @param pubKey    公钥
     * @param nonce     大整数
     * @param secretMsg 消息密文
     * @return
     */
    public static String decrypt(String priKey, String pubKey, Long nonce, String secretMsg) {
        return decryptMessage(new Wif(priKey).getPrivateKey(), new Address(pubKey).getPublicKey(), BigInteger.valueOf(nonce), Util.hexToBytes(secretMsg));
    }

    /**
     * 数据解密
     *
     * @param priKey    私钥
     * @param pubKey    公钥
     * @param nonce     大整数
     * @param secretMsg 消息密文
     * @return
     */
    public static String decrypt(String priKey, String pubKey, Long nonce, byte[] secretMsg) {
        return decryptMessage(new Wif(priKey).getPrivateKey(), new Address(pubKey).getPublicKey(), BigInteger.valueOf(nonce), secretMsg);
    }

    private static String decryptMessage(PrivateKey privateKey, PublicKey publicKey, BigInteger nonce, byte[] message) {
        String plaintext = "";
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");

            // Getting nonce bytes
            String stringNonce = nonce.toString();
            byte[] nonceBytes = Arrays.copyOfRange(Util.hexlify(stringNonce), 0, stringNonce.length());

            // Getting shared secret
            byte[] secret = publicKey.getKey().getPubKeyPoint().multiply(privateKey.getKey().getPrivKey()).normalize().getXCoord().getEncoded();

            // SHA-512 of shared secret
            byte[] ss = sha512.digest(secret);

            byte[] seed = Bytes.concat(nonceBytes, Util.hexlify(Util.bytesToHex(ss)));

            // Applying decryption
            byte[] temp = Util.decryptAES(message, seed);
            assert temp != null;
            byte[] checksum = Arrays.copyOfRange(temp, 0, 4);
            byte[] decrypted = Arrays.copyOfRange(temp, 4, temp.length);
            plaintext = new String(decrypted);
            byte[] checksumConfirmation = Arrays.copyOfRange(sha256.digest(decrypted), 0, 4);
            boolean checksumVerification = Arrays.equals(checksum, checksumConfirmation);
            Preconditions.checkArgument(checksumVerification, "Invalid checksum found while performing decryptio");
        } catch (NoSuchAlgorithmException e) {
            LOGGER.info("NoSuchAlgotithmException. Msg:" + e.getMessage());
        }
        return plaintext;
    }

    private static byte[] encryptMessage(PrivateKey privateKey, PublicKey publicKey, BigInteger nonce, String message) {
        byte[] encrypted = null;
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");

            // Getting nonce bytes
            String stringNonce = nonce.toString();
            byte[] nonceBytes = Arrays.copyOfRange(Util.hexlify(stringNonce), 0, stringNonce.length());

            // Getting shared secret
            byte[] secret = publicKey.getKey().getPubKeyPoint().multiply(privateKey.getKey().getPrivKey()).normalize().getXCoord().getEncoded();

            // SHA-512 of shared secret
            byte[] ss = sha512.digest(secret);

            byte[] seed = Bytes.concat(nonceBytes, Util.hexlify(Util.bytesToHex(ss)));

            // Calculating checksum
            byte[] sha256Msg = sha256.digest(message.getBytes());
            byte[] checksum = Arrays.copyOfRange(sha256Msg, 0, 4);

            // Concatenating checksum + message bytes
            byte[] msgFinal = Bytes.concat(checksum, message.getBytes());

            // Applying encryption
            encrypted = Util.encryptAES(msgFinal, seed);
        } catch (NoSuchAlgorithmException ex) {
            LOGGER.info("NoSuchAlgotithmException. Msg:" + ex.getMessage());
        }
        return encrypted;

    }

    public static void main(String[] args) {
        int errorCount = 0;

        for (int i = 0; i < 100; i++) {
            for (int j = 0; j < 10000; j++) {
                String priKey = "5JLL3mqAFt2YHVJf8W3h9oUPP2sjceLYSSyEbSt1yMjeucxGH98";
                String pubKey = "GXC7XzFVivuBtuc2rz3Efkb41JCN4KH7iENAx9rch9QkowEmc4UvV";
                Long nonce = Long.valueOf(RandomStringUtils.randomNumeric(10));

                String priKey1 = "5Ka9YjFQtfUUX2DdnqkaPWH1rVeSeby7Cj2VdjRt79S9kKLvXR7";
                String pubKey1 = "GXC67KQNpkkLUzBgDUkWqEBtojwqPgL78QCmTRRZSLugzKEzW4rSm";
                String message1 = RandomStringUtils.random(i);
                String strEn = MsgCryptUtil.encrypt(priKey1, pubKey1, nonce, message1);
                String strDe = MsgCryptUtil.decrypt(priKey, pubKey, nonce, strEn);

                if (!strDe.equals(message1)) {
                    errorCount++;
                }
            }
        }

        System.out.println("error count:" + errorCount);
    }
}
