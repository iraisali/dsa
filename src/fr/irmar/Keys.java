package fr.irmar;

import utils.Constants;
import utils.Tools;

import java.math.BigInteger;

public class Keys {
    private BigInteger privkey;
    private BigInteger pubkey;
    //private BigInteger tmpkey;

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

    /*public BigInteger getTmpkey() {
        return tmpkey;
    }*/

    /*public void setTmpkey(BigInteger tmpkey) {
        this.tmpkey = tmpkey;
    }*/


    //TODO constructor ? la j'ai une méthode dans Tools mais j'sais meme pas quoi en faire ..
    public Keys() {

    }
}
