package service;

import fr.irmar.Keys;
import fr.irmar.SecretNumber;
import fr.irmar.Signature;
import fr.irmar.SignatureException;
import utils.Constants;

import java.math.BigInteger;
import java.util.ArrayList;

import static utils.Tools.*;

public class Main {
    public static void main(String[] args) {
        //déclaration + initialisation des vars
        Constants currentConstant = new Constants();
        Keys currentKeys = keysGen(currentConstant.getP(),currentConstant.getQ(),currentConstant.getG());

        ArrayList signatureList = signMessage("alice",currentKeys,currentConstant);

        saveSign2(signatureList,"output");

        try{
            signsFromFileVerification("output","alice",currentKeys,currentConstant);
            System.out.println("tout est ok.");
        }catch(SignatureException e){
            System.out.println("erreur.");
        }
        int n = 10000;
        SecretNumber currentSecreetNum = secretNumGen(currentConstant.getP(),currentConstant.getQ());
        long N = manySignatures(n,"bonjour, comment ca va?",currentKeys,currentConstant);
        System.out.println("Le temps de calcul de "+n+" signatures est de "+N+" nanosecondes.");
    }
}
