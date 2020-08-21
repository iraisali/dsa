package service;

import fr.irmar.Keys;
import fr.irmar.SignatureException;
import utils.Constants;

import java.io.IOException;
import java.util.ArrayList;

import static utils.Tools.*;

public class Main {
    public static void main(String[] args) {

        //purge error Signature file.
    	try {
			WriteService.purgeFile(Constants.errorSignatureFile);
		} catch (IOException e1) {
            e1.printStackTrace();
        }

    	Parser.firstArg(args);

    }


}
