package com.gxchain.common.signature.utils;

import org.bouncycastle.crypto.signers.RandomDSAKCalculator;
import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.params.*;
import org.spongycastle.crypto.signers.DSAKCalculator;
import org.spongycastle.crypto.signers.ECDSASigner;
import org.spongycastle.math.ec.ECAlgorithms;
import org.spongycastle.math.ec.ECMultiplier;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.math.ec.FixedPointCombMultiplier;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * @Description
 * @Author Hanawa
 * @Date 2018/3/1
 * @Version 1.0
 */
public class MyECDSASigner extends ECDSASigner {
    private final DSAKCalculator kCalculator;
    private ECKeyParameters key;
    private SecureRandom random;

    public MyECDSASigner() {
        this.kCalculator = (DSAKCalculator) new RandomDSAKCalculator();
    }

    public MyECDSASigner(DSAKCalculator kCalculator) {
        this.kCalculator = kCalculator;
    }

    public void init(boolean forSigning, CipherParameters param) {
        SecureRandom providedRandom = null;
        if (forSigning) {
            if (param instanceof ParametersWithRandom) {
                ParametersWithRandom rParam = (ParametersWithRandom)param;
                this.key = (ECPrivateKeyParameters)rParam.getParameters();
                providedRandom = rParam.getRandom();
            } else {
                this.key = (ECPrivateKeyParameters)param;
            }
        } else {
            this.key = (ECPublicKeyParameters)param;
        }

        this.random = this.initSecureRandom(forSigning && !this.kCalculator.isDeterministic(), providedRandom);
    }

    public BigInteger[] generateSignature(byte[] message) {
        ECDomainParameters ec = this.key.getParameters();
        BigInteger n = ec.getN();
        BigInteger e = this.calculateE(n, message);
        BigInteger d = ((ECPrivateKeyParameters)this.key).getD();
        if (this.kCalculator.isDeterministic()) {
            this.kCalculator.init(n, d, message);
        } else {
            this.kCalculator.init(n, this.random);
        }

        ECMultiplier basePointMultiplier = this.createBasePointMultiplier();

        BigInteger r;
        BigInteger s;
        do {
            BigInteger k;
            do {
                k = this.kCalculator.nextK();
                ECPoint p = basePointMultiplier.multiply(ec.getG(), k).normalize();
                r = p.getAffineXCoord().toBigInteger().mod(n);
            } while(r.equals(ZERO));

            s = k.modInverse(n).multiply(e.add(d.multiply(r))).mod(n);
        } while(s.equals(ZERO));

        return new BigInteger[]{r, s};
    }

    public boolean verifySignature(byte[] message, BigInteger r, BigInteger s) {
        ECDomainParameters ec = this.key.getParameters();
        BigInteger n = ec.getN();
        BigInteger e = this.calculateE(n, message);
        if (r.compareTo(ONE) >= 0 && r.compareTo(n) < 0) {
            if (s.compareTo(ONE) >= 0 && s.compareTo(n) < 0) {
                BigInteger c = s.modInverse(n);
                BigInteger u1 = e.multiply(c).mod(n);
                BigInteger u2 = r.multiply(c).mod(n);
                ECPoint G = ec.getG();
                ECPoint Q = ((ECPublicKeyParameters)this.key).getQ();
                ECPoint point = ECAlgorithms.sumOfTwoMultiplies(G, u1, Q, u2).normalize();
                if (point.isInfinity()) {
                    return false;
                } else {
                    BigInteger v = point.getAffineXCoord().toBigInteger().mod(n);
                    return v.equals(r);
                }
            } else {
                return false;
            }
        } else {
            return false;
        }
    }

    protected BigInteger calculateE(BigInteger n, byte[] message) {
        int log2n = n.bitLength();
        int messageBitLength = message.length * 8;
        BigInteger e = new BigInteger(1, message);
        if (log2n < messageBitLength) {
            e = e.shiftRight(messageBitLength - log2n);
        }

        return e;
    }

    protected ECMultiplier createBasePointMultiplier() {
        return new FixedPointCombMultiplier();
    }

    protected SecureRandom initSecureRandom(boolean needed, SecureRandom provided) {
        return !needed ? null : (provided != null ? provided : new SecureRandom());
    }
}
