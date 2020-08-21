package utils;

import java.math.BigInteger;

public class Constants {
    //p = nbre premier et taille du groupe
    //q = diviseur premier de p-1
    //g = generateur du sgpe d'ordre q
    private BigInteger p;
    private BigInteger q;
    private BigInteger g;

    public static String separator = " | ";
    //public static String inputMessageFile = "alice";
    public static String outputSignatureFile = "output_signatures";
    public static String errorSignatureFile = "errors_signatures";
    public static String outputPublicKeyFile = "public_key";


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

    //Given values
    public Constants(){
        //System.out.println("creation des constantes:");
        setQ(BigInteger.valueOf(7).add(BigInteger.valueOf(2).pow(160)));
        /* p = 1 + (Math.pow(2, 160) + 7)*(Math.pow(2, 864)+218); */
        BigInteger r = BigInteger.valueOf(218).add(BigInteger.valueOf(2).pow(864));
        setP(BigInteger.valueOf(1).add(q.multiply(r)));
        //$g = 2^{(p-1)/q} \mod p$
        setG(BigInteger.valueOf(2).modPow(r, p));
    }

}
