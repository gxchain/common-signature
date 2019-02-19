package com.gxchain.common.signature.crypto.ec;


import com.gxchain.common.signature.crypto.digest.Ripemd160;
import com.gxchain.common.signature.crypto.digest.Sha256;
import com.gxchain.common.signature.crypto.util.Base58;
import com.gxchain.common.signature.crypto.util.BitUtils;
import com.gxchain.common.signature.utils.RefValue;
import org.apache.commons.lang3.StringUtils;

import java.util.Arrays;

public class GxcEcUtil {
    public static final String GXC_PREFIX = "GXC";
    public static final String GXC_Sign = "SIG_K1_";

    public static final String PREFIX_K1 = "K1";
    public static final String PREFIX_R1 = "R1";

    public static byte[] parseKeyBase58(String base58Key, RefValue<CurveParam> curveParamRef, RefValue<Long> checksumRef) {

        final byte[] retKeyData;

        final String typePrefix;
        if (base58Key.startsWith(GXC_PREFIX)) {
            if (base58Key.startsWith(PREFIX_K1, GXC_PREFIX.length())) {
                typePrefix = PREFIX_K1;
            } else if (base58Key.startsWith(PREFIX_R1, GXC_PREFIX.length())) {
                typePrefix = PREFIX_R1;
            } else {
                typePrefix = null;
            }

            retKeyData = getBytesIfMatchedRipemd160(base58Key.substring(GXC_PREFIX.length()), typePrefix, checksumRef);
        } else {
            typePrefix = null;
            retKeyData = getBytesIfMatchedSha256(base58Key, checksumRef);
        }

        if (curveParamRef != null) {
            curveParamRef.data = EcTools.getCurveParam(PREFIX_R1.equals(typePrefix) ? CurveParam.SECP256_R1 : CurveParam.SECP256_K1);
        }

        return retKeyData;
    }

    private static byte[] getBytesIfMatchedRipemd160(String base58Data, String prefix, RefValue<Long> checksumRef) {
        byte[] prefixBytes = StringUtils.isEmpty(prefix) ? new byte[0] : prefix.getBytes();

        byte[] data = Base58.decode(base58Data.substring(prefixBytes.length));

        byte[] toHashData = new byte[data.length - 4 + prefixBytes.length];
        System.arraycopy(data, 0, toHashData, 0, data.length - 4); // key data

        System.arraycopy(prefixBytes, 0, toHashData, data.length - 4, prefixBytes.length);

        Ripemd160 ripemd160 = Ripemd160.from(toHashData); //byte[] data, int startOffset, int length
        long checksumByCal = BitUtils.uint32ToLong(ripemd160.bytes(), 0);
        long checksumFromData = BitUtils.uint32ToLong(data, data.length - 4);
        if (checksumByCal != checksumFromData) {
            throw new IllegalArgumentException("Invalid format, checksum mismatch");
        }

        if (checksumRef != null) {
            checksumRef.data = checksumFromData;
        }

        return Arrays.copyOfRange(data, 0, data.length - 4);
    }

    private static byte[] getBytesIfMatchedSha256(String base58Data, RefValue<Long> checksumRef) {
        byte[] data = Base58.decode(base58Data);

        //
        Sha256 checkOne = Sha256.from(data, 0, data.length - 4);
        Sha256 checkTwo = Sha256.from(checkOne.getBytes());
        if (checkTwo.equalsFromOffset(data, data.length - 4, 4)
                || checkOne.equalsFromOffset(data, data.length - 4, 4)) {

            if (checksumRef != null) {
                checksumRef.data = BitUtils.uint32ToLong(data, data.length - 4);
            }

            return Arrays.copyOfRange(data, 1, data.length - 4);
        }

        throw new IllegalArgumentException("Invalid format, checksum mismatch");
    }
}
