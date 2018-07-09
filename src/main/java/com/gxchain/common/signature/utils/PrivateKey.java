package com.gxchain.common.signature.utils;

import org.bitcoinj.core.ECKey;

import java.io.Serializable;

/**
 * @Author Hanawa
 * @Date 2018/2/28
 * @Version 1.0
 */
public class PrivateKey implements ByteSerializable, Serializable {

    private ECKey privateKey;


    public PrivateKey(ECKey key) {
        if (key.isPubKeyOnly()) {
            throw new IllegalStateException("Passing a private key to PublicKey constructor");
        }
        this.privateKey = key;
    }

    public ECKey getKey() {
        return privateKey;
    }

    @Override
    public byte[] toBytes() {
        return privateKey.getPrivKeyBytes();
    }

    public String toWif() {
        ECKey pk = ECKey.fromPrivate(privateKey.getPrivKey());
        return new Wif(pk).toString();
    }

    @Override
    public int hashCode() {
        return privateKey.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        PublicKey other = (PublicKey) obj;
        return this.privateKey.equals(other.getKey());
    }

    public static PrivateKey fromBuffer(byte[] buffer) {
        return new PrivateKey(ECKey.fromPrivate(buffer));
    }
}
