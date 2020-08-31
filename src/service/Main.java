package service;

import utils.Constants;

import java.io.IOException;

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
