package service;

import fr.irmar.Keys;
import fr.irmar.SignatureException;
import utils.Constants;

import java.io.IOException;
import java.util.ArrayList;

import static service.WriteService.savePublicKeyInFile;
import static service.WriteService.saveSignatureInFile;
import static utils.Tools.*;

public class Parser {

    //First argument
    public static void firstArg(String[] Args){

        //test mode
        if(Args[0].compareTo("test") == 0){

            int n = Integer.parseInt(Args[1]); //comment faire dans le cas où l'argument n'est pas convertible en un entier ??
            Constants currentConstant = new Constants();
            Keys currentKeys = keysGen(currentConstant.getP(),currentConstant.getQ(),currentConstant.getG());
            String message = "bonjour, ca va ?";
            long N = manySignatures(n,message,currentKeys,currentConstant);
            System.out.println("Le temps de calcul de "+n+" signatures est de "+N+" nanosecondes.");
        }

        //verification mode
        else if(Args[0].compareTo("verif") == 0){

            Constants currentConstant = new Constants();
            Keys currentKeys = keyFromFile(Constants.outputPublicKeyFile);
            String MessagesFileName = Args[1];

            try{
                signsFromFileVerification(Constants.outputSignatureFile,MessagesFileName,currentKeys,currentConstant);
                //System.out.println("tout est ok.");

            }catch(SignatureException e){
                System.out.println("erreur.");
            }
        }

        //
        else if(Args[0].compareTo("sign") == 0){
            try {
                WriteService.purgeFile(Constants.outputSignatureFile);
            } catch (IOException e1) {
                e1.printStackTrace();
            }

            String MessagesFileName = Args[1];
            Constants currentConstant = new Constants();

            Keys currentKeys = keysGen(currentConstant.getP(),currentConstant.getQ(),currentConstant.getG());
            savePublicKeyInFile(currentKeys,Constants.outputPublicKeyFile);

            ArrayList signatureList = signMessage(MessagesFileName,currentKeys,currentConstant);
            saveSignatureInFile(signatureList,Constants.outputSignatureFile);
        }

        else if(Args[0].compareTo("help") == 0){

        }
    }
}
