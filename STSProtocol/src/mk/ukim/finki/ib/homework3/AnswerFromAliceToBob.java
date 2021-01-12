package mk.ukim.finki.ib.homework3;

public class AnswerFromAliceToBob {
    private byte [] cipheredSignature;

    public AnswerFromAliceToBob(byte[] cipheredSignature) {
        this.cipheredSignature = cipheredSignature;
    }

    public byte[] getCipheredSignature() {
        return cipheredSignature;
    }
}
