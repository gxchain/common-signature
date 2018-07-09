package com.gxchain.common.signature.utils;

import com.google.common.base.Preconditions;
import com.google.common.primitives.Bytes;
import org.bitcoinj.core.Base58;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;

import java.util.Arrays;

/**
 * @Author Hanawa
 * @Date 2018/2/28
 * @Version 1.0
 */
public class Wif {
    private static final int VERSION = 0x80;

    private PrivateKey privateKey;
    private int version;

    public Wif(ECKey ecKey) {
        this.privateKey = new PrivateKey(ecKey);
        this.version = VERSION;
    }

    public Wif(PrivateKey privateKey, int version) {
        this.privateKey = privateKey;
        this.version = version;
    }

    public Wif(String privateKeyStr) {
        this.version = VERSION;
        byte[] decoded = Base58.decode(privateKeyStr);
        Preconditions.checkArgument(Math.abs(decoded[0]) == version, "error version || valid privateKeyStr");
        byte[] priByte = Arrays.copyOfRange(decoded, 0, decoded.length - 4);
        byte[] checkSum = Arrays.copyOfRange(decoded, decoded.length - 4, decoded.length);
        byte[] calculateCheckSum = calculateChecksum(priByte);
        Preconditions.checkArgument(Arrays.deepEquals(new byte[][]{checkSum}, new byte[][]{calculateCheckSum}), "checkSum error");

        this.privateKey = new PrivateKey(ECKey.fromPrivate(Arrays.copyOfRange(priByte, 1, priByte.length)));
    }

    @Override
    public String toString() {
        byte[] priKey = this.privateKey.toBytes();
        byte[] version = {(byte) VERSION};
        byte[] result = Bytes.concat(version, priKey);
        return Base58.encode(Bytes.concat(result, calculateChecksum(result)));
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    private byte[] calculateChecksum(byte[] data) {
        return Arrays.copyOfRange(Sha256Hash.hashTwice(data), 0, 4);
    }
}
