package mk.ukim.finki.ib.homework3;

import java.math.BigInteger;

public class AnswerFromBobToAlice {
    private BigInteger gy;
    private byte [] cipheredSignature;

    public AnswerFromBobToAlice(BigInteger gy, byte[] cipheredSignature) {
        this.gy = gy;
        this.cipheredSignature = cipheredSignature;
    }

    public BigInteger getGy() {
        return gy;
    }

    public byte[] getCipheredSignature() {
        return cipheredSignature;
    }
}
