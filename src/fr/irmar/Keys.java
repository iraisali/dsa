package fr.irmar;

import utils.Constants;
import utils.Tools;

import java.math.BigInteger;

public class Keys {
    private BigInteger privkey;
    private BigInteger pubkey;

    public BigInteger getPrivkey() {
        return privkey;
    }

    public void setPrivkey(BigInteger privkey) {
        this.privkey = privkey;
    }

    public BigInteger getPubkey() {
        return pubkey;
    }

    public void setPubkey(BigInteger pubkey) {
        this.pubkey = pubkey;
    }

    public Keys() {
    }
}
