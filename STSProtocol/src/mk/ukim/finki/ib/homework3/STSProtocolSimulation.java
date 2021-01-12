package mk.ukim.finki.ib.homework3;

import java.math.BigInteger;

/**
 * @author: GABRIEL DIMITRIEVSKI
 */
public class STSProtocolSimulation {
    public static void main(String[] args) throws Exception {

        BigInteger g = new BigInteger("111111");

        User Alice = new User("Alice",g);
        User Bob = new User("Bob",g);

        Alice.generatePublicAndPrivateKey();
        Bob.generatePublicAndPrivateKey();

        BigInteger gx = Alice.AliceComputeExponentialAndRandomNumber();
        BigInteger gy = Bob.BobComputeExponentialAndRandomNumber();

        Alice.setBobExponential(gy);
        Bob.setAliceExponential(gx);

        Alice.setSecoundUserPublicKey(Bob.getPublicKey());
        Bob.setSecoundUserPublicKey(Alice.getPublicKey());

        Bob.BobSharedKeyCalculation();
        AnswerFromBobToAlice answerFromBobToAlice = Bob.BobCipherSignAndConcatenate();

        Alice.AliceSharedKeyCalculation();
        Alice.AliceDecryptionAndVerification(answerFromBobToAlice);

        AnswerFromAliceToBob answerFromAliceToBob = Alice.AliceCipherSignAndConcatenate();
        Bob.BobDecryptionAndVerification(answerFromAliceToBob);
        System.out.println("AUTHENTICATION FINISHED SUCCESSFULLY");
    }
}
