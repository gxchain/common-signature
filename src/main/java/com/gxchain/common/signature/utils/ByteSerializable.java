package com.gxchain.common.signature.utils;

/**
 * Interface implemented by all entities for which makes sense to have a byte-array representation.
 */
public interface ByteSerializable {

    byte[] toBytes();
}
