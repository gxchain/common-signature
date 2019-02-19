package com.gxchain.common.signature;

import com.gxchain.common.signature.crypto.digest.Sha256;
import com.gxchain.common.signature.crypto.ec.GxcPrivateKey;
import com.gxchain.common.signature.crypto.ec.GxcPublicKey;
import com.gxchain.common.signature.utils.*;

/**
 * @author liruobin
 * @since 2019-02-19
 */
public class SignatureUtil {

    public static String signature(String data, String priKey) {
        return Util.bytesToHex(signature(data.getBytes(), priKey));
    }

    public static byte[] signature(byte[] data, String priKey) {
        GxcPrivateKey gxcPrivateKey = new GxcPrivateKey(priKey);
        Sha256 msg = Sha256.from(data);
        return gxcPrivateKey.sign(msg).encoding(true);
    }

    public static boolean verify(String data, String sign, String pubKey) {
        return verify(data.getBytes(), sign, pubKey);
    }

    public static boolean verify(byte[] data, String sign, String pubKey) {
        return verify(data, Util.hexToBytes(sign), pubKey);
    }

    public static boolean verify(byte[] data, byte[] sign, String pubKey) {
        GxcPublicKey publicKey = new GxcPublicKey(pubKey);
        Sha256 msg = Sha256.from(data);
        return publicKey.verify(msg.getBytes(), sign);
    }
}
