package utils;

import java.math.BigInteger;

public class Tests {
    private BigInteger p;
    private BigInteger q;
    private BigInteger g;

    public BigInteger getP() {
        return p;
    }

    public void setP(BigInteger setp) {
        p = setp;
    }

    public BigInteger getQ() {
        return q;
    }

    public void setQ(BigInteger setq) {
        q = setq;
    }

    public BigInteger getG() {
        return g;
    }

    public void setG(BigInteger setg) {
        g = setg;
    }

    //Ces valeurs sont données par le prof
    public Tests(){
        setQ(BigInteger.valueOf(13));
        setP(BigInteger.valueOf(53));
        setG(BigInteger.valueOf(2));
    }
}
