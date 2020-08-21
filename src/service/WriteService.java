package service;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import fr.irmar.Keys;
import fr.irmar.Signature;
import utils.Constants;

public class WriteService {

	//save signatures in a file
	//One signature couple in each line
	//format: R | S
	public static void saveSignatureInFile(ArrayList<Signature> currentSign, String fileOutName){
        try (
        		FileWriter fileOut = new FileWriter(fileOutName);
        		BufferedWriter bufferLine = new BufferedWriter(fileOut)
            )
        {
        	PrintWriter sortie = new PrintWriter(bufferLine);
        	String line = null;
        	for (Signature sign:currentSign)
        	{
   				// format de l aligne dans le fichier: R | S
        		sortie.println(sign.getR().toString()+Constants.separator+sign.getS().toString());
        	}

        	sortie.flush();
        	sortie.close();
        }catch (IOException e){
            e.printStackTrace();
        }
    }

    //save the public key in a file
 	public static void savePublicKeyInFile(Keys currentKeys, String fileOutName){
        try (
        		FileWriter fileOut = new FileWriter(fileOutName);
        		BufferedWriter bufferLine = new BufferedWriter(fileOut)
            )
        {
        	PrintWriter sortie = new PrintWriter(bufferLine);
        	//String line = null;
			sortie.println(currentKeys.getPubkey().toString());
        	sortie.flush();
        	sortie.close();
        }catch (IOException e){
            e.printStackTrace();
        }
    }

	//Write eventual signature errors in a file
	public static void writeErrorSignatureLine(List<Integer> errorsLines){
        try (
        		FileWriter fileOut = new FileWriter(Constants.errorSignatureFile);
        		BufferedWriter bufferLine = new BufferedWriter(fileOut)
            )
        {
        	PrintWriter sortie = new PrintWriter(bufferLine);
        	String line = null;

			for (int numLine : errorsLines) {
				//ecriture dans le fichier
				sortie.println("Erreur de signature sur la ligne : " + numLine);

				//Affichage sur la console
				//System.out.println("Erreur de signature sur la ligne : "+numLine);
				System.out.println("Wrong Signature on " + (numLine) + "-th line");
			}

        	sortie.flush();
        	sortie.close();
        }catch (IOException e){
            e.printStackTrace();
        }
    }

	// purger un fichier (vider son contenu)
	public static void purgeFile(String fileToPurge) throws IOException{
		new FileWriter(new File(fileToPurge)).close();
    }

}