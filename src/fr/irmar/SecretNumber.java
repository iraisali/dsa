package fr.irmar;

import java.math.BigInteger;

public class SecretNumber {
    BigInteger secretNum;
    BigInteger invSecret;

    public BigInteger getSecretNum() {
        return secretNum;
    }

    public void setSecretNum(BigInteger secretNum) {
        this.secretNum = secretNum;
    }

    public BigInteger getInvSecret() {
        return invSecret;
    }

    public void setInvSecret(BigInteger invSecret) {
        this.invSecret = invSecret;
    }

    public SecretNumber(){

    }
}
