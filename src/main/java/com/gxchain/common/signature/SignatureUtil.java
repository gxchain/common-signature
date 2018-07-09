package com.gxchain.common.signature;

import com.gxchain.common.signature.utils.*;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.ECKey.ECDSASignature;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Utils;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import java.math.BigInteger;

/**
 * Created by DOmmy on 2018/1/31.
 */
public class SignatureUtil {


    public static boolean verify(String data, String sign, String pubKey) {
        return verify(data.getBytes(), sign, pubKey);
    }

    public static boolean verify(byte[] data, String sign, String pubKey) {
        return verify(data, sign, pubKey, false);
    }

    public static boolean verify(byte[] data, String sign, String pubKey, boolean isCheck) {
        byte[] sigData = Util.hexToBytes(sign);
        // 添加校验位判断

        if (isCheck && (((sigData[1] & 0x80) != 0) || (sigData[1] == 0) || ((sigData[2] & 0x80) != 0) || ((sigData[33] & 0x80) != 0) || (sigData[33]
                == 0) || ((sigData[34] & 0x80) != 0))) {
            return false;
        }
        // sigBtyes = ByteUtils.subArray(sigBtyes, 1);

        BigInteger r = new BigInteger(ByteUtils.subArray(sigData, 1, 33));
        BigInteger s = new BigInteger(ByteUtils.subArray(sigData, 33));
        //        LOGGER.info("r:" + r + ",s:" + s);
        // SignatureECDSA SHA256
        ECDSASignature signature = new ECDSASignature(r, s);
        Address from = new Address(pubKey);
        PublicKey pk1 = from.getPublicKey();
        byte[] hash = Sha256Hash.hash(data);
        if (pk1.getKey().verify(hash, signature.encodeToDER()))
            return true;
        else { // Utils.bigIntegerToBytes转换成固定长度的byte[]时 第一位为0时会忽略 导致从byte[]转换成BigInteger出错 r存在该情况
            r = new BigInteger(ByteUtils.concatenate(new byte[] {0}, ByteUtils.subArray(sigData, 1, 33)));
            signature = new ECDSASignature(r, s);
            return pk1.getKey().verify(hash, signature.encodeToDER());
        }
    }


    public static String signature(String data, String priKey) {
        return signature(data.getBytes(), priKey);
    }

    public static String signature(byte[] data, String priKey) {
        Wif wif = new Wif(priKey);
        PrivateKey pk = wif.getPrivateKey();
        byte[] hash = Sha256Hash.hash(data);
        Sha256Hash sha256Hash = Sha256Hash.wrap(hash);
        ECDSASignature signature = pk.getKey().sign(sha256Hash);

        // 计算值 输出
        byte[] sigData;
        int recId = -1;

        for (int i = 0; i < 4; i++) {
            ECKey k = ECKey.recoverFromSignature(i, signature, sha256Hash, pk.getKey().isCompressed());
            if (k != null && k.getPubKeyPoint().equals(pk.getKey().getPubKeyPoint())) {
                recId = i;
                break;
            }
        }
        sigData = new byte[65];  // 1 header + 32 bytes for R + 32 bytes S for SigData
        int headerByte = recId + 27 + (pk.getKey().isCompressed() ? 4 : 0);
        sigData[0] = (byte) headerByte;
        System.arraycopy(Utils.bigIntegerToBytes(signature.r, 32), 0, sigData, 1, 32);
        System.arraycopy(Utils.bigIntegerToBytes(signature.s, 32), 0, sigData, 33, 32);

        return Util.byteToString(sigData);
    }

//    public static void main(String[] args) throws MalformedAddressException {
//        LOGGER.info(SignatureUtil.verify("{\"account\":\"init0\",\"userId\":\"5A5BE9qnbLqjrbai57602863\"}"
//                ,"20365170dfb15b5303d4f470e229a7ebec3a17f15e0af86cb6db027bd81ba1f383136c4bfdbf702c541c4c9ec1e47f2b3e20655983f7cb81525ffe807e1e44cf9d"
//                ,"GXC6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV"));
//    }

}
