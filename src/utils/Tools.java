package utils;

import fr.irmar.Keys;
import fr.irmar.SecretNumber;
import fr.irmar.Signature;
import fr.irmar.SignatureException;
import service.WriteService;

import java.io.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Random;

public class Tools {

    //in : integer 'lenth'
    //out: Random BigInteger, with bit lenth = 'lenth'
    public static BigInteger bigRandGen(int lenth){
        Random rnd = new Random();
        BigInteger n = new BigInteger(lenth,rnd);
        return n;
    }

    //write Signatures from ArrayList in a file
    //Version 1: object format
    public static void saveSign(ArrayList<Signature> currentSign, String fileOutName){
        try(FileOutputStream fileOut = new FileOutputStream(fileOutName);
            ObjectOutputStream buffer = new ObjectOutputStream(fileOut)) //ce mode de déclaration permet de close() automatiquement
        {
            buffer.writeObject(currentSign);
        }catch (IOException e){
            e.printStackTrace();
        }
    }

    //Version 2: String Format (R1|S1|R2 ... |Sn)
    public static void saveSign2(ArrayList<Signature> currentSign, String fileOutName){

        WriteService.saveSignatureInFile(currentSign,fileOutName);

    }

    //Version 3: 2 separates files.
    public static void saveSign3(ArrayList<Signature> currentSign, String fileOutName1, String fileOutName2){
        try(FileWriter fileOut = new FileWriter(fileOutName1);
            FileWriter fileOut2 = new FileWriter(fileOutName2);
            BufferedWriter bufferLineR = new BufferedWriter(fileOut);
            BufferedWriter bufferLineS = new BufferedWriter(fileOut2)) {
            String line = null;
            for(Signature sign:currentSign){
                line = sign.getR().toString();
                line = line.concat("-");
                bufferLineR.write(line);
                line = sign.getS().toString();
                line = line.concat("-");
                bufferLineS.write(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    //Key Generation (see B1 page 47)
    //TODO fct qui vérifie si le couple (L,N) est un couple du standard cf. section 4.2
    //TODO gestion des erreurs
    public static Keys keysGen(BigInteger p, BigInteger q, BigInteger g) {
        Keys K = new Keys();
        int L = p.bitLength();
        int N = q.bitLength();
        //check validity du couple (L,N)
        BigInteger c = Tools.bigRandGen(N + 64); //on compte en bit, c ne doit pas etre negatif
        K.setPrivkey((c.mod(q.add(BigInteger.valueOf(-1)))).add(BigInteger.valueOf(1)));
        K.setPubkey(g.modPow(K.getPrivkey(), p));
        return K;
    }

    //take public key from a file
    public static Keys keyFromFile(String keyFileName){
        Keys currentKeys = new Keys();
        try(FileReader file = new FileReader(keyFileName);
            BufferedReader buffer = new BufferedReader(file)) {

            currentKeys.setPubkey(new BigInteger(buffer.readLine()));

        } catch (IOException e) {
            e.printStackTrace();
        }
        return currentKeys;
    }

    //Secret Number generator (for each message)
    public static SecretNumber secretNumGen(BigInteger p, BigInteger q){
        SecretNumber currentSecret = new SecretNumber();
        int L = p.bitLength();
        int N = q.bitLength();

        BigInteger c = Tools.bigRandGen(N + 64); //on compte en bit
        currentSecret.setSecretNum((c.mod(q.add(BigInteger.valueOf(-1)))).add(BigInteger.valueOf(1)));
        currentSecret.setInvSecret((currentSecret.getSecretNum()).modInverse(q));
        return currentSecret;
    }

    //Sign messages from a file (Supposing every line is a message)
    //in: file name, Keys, Constants and
    //out: arrayList with all signatures
    public static ArrayList signMessage(String sourcename, Keys currentKeys, Constants currentConstants){
        ArrayList<Signature>  signatureList = new ArrayList<Signature>();

        try (FileReader reader = new FileReader(sourcename);
             BufferedReader buffer = new BufferedReader(reader)){
            String line;
            while ((line = buffer.readLine()) != null){

                //BigInteger hashline = hashComputing("sha-1",line);
                BigInteger hashline = hashComputing("MD5",line);
                SecretNumber currentSecretNum = secretNumGen(currentConstants.getP(),currentConstants.getQ());
                signatureList.add(dsaSignature(hashline,currentKeys,currentConstants,currentSecretNum));
            }

        } catch (IOException e) {
            e.printStackTrace();
        }

        return signatureList;
    }

    //Compute hash from
    //in: - Name of an hash algorithm
    // - message to hash
    //out: hash (BigInteger)
    public static BigInteger hashComputing(String algo, String message){
        byte[] digest = null;
        try {
            MessageDigest sha = MessageDigest.getInstance(algo);
            sha.update(message.getBytes());
            digest = sha.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        BigInteger hash = new BigInteger(digest);
        if(hash.compareTo(BigInteger.valueOf(0)) == -1){ //is it requisite ?
            hash = hash.negate();
        }
        return hash;
    }

    //Signature function
    //in: hash, keys and constants
    //out: Signature
    public static Signature dsaSignature(BigInteger currentHash, Keys currentKeys, Constants currentConstants, SecretNumber currentSecret){
        Signature currentSignature = new Signature();
        //System.out.println(currentConstants.getG().modPow(currentSecret.getsecretNum(), currentConstants.getP()).mod(currentConstants.getQ()));
        if(currentSecret.getSecretNum() != null && currentConstants.getP() != null && currentConstants.getQ() != null){
            currentSignature.setR((currentConstants.getG().modPow(currentSecret.getSecretNum(), currentConstants.getP())).mod(currentConstants.getQ()));
        }
        else{
            System.out.println("Null power.");
            System.exit(42);
        }

        int M = currentHash.bitLength();
        int N = currentConstants.getQ().bitLength(); // il n'y a pas besoin de currentConstantsidérer le min comme dans la doc (?)

        BigInteger z;
        z = currentHash.shiftRight(Math.max(0,M-N)); //FIXME: s'assure que c'est equivalent a prendre les min(M,N) bits les plus a gauche
        currentSignature.setS(((currentSecret.getInvSecret()).multiply(z.add(currentKeys.getPrivkey().multiply(currentSignature.getR())))).mod(currentConstants.getQ()));
        return currentSignature;
    }

    //Read signatures
    //Version 1: file contain Signatures
    public static ArrayList<Signature> readSignaturesString(String fileName){
        ArrayList<Signature> signList = new ArrayList<Signature>();
        try (FileReader file = new FileReader(fileName);

             BufferedReader buffer = new BufferedReader(file)){

            String line;

            while((line = buffer.readLine()) != null){
                Signature sign = new Signature();
                String splitSignature[] = line.split(Constants.separator);

                //format : R | S
                sign.setR(new BigInteger(splitSignature[0]));
                sign.setS(new BigInteger(splitSignature[2]));
                signList.add(sign);
            }
        }catch (IOException e){
            e.printStackTrace();
        }
        return signList;
    }

    //Version 3: Signatures from 2 files
    public static ArrayList<Signature> readSignaturesString2(String fileNameR, String fileNameS){
        ArrayList<Signature> signList = new ArrayList<Signature>();
        try(FileReader fileR = new FileReader(fileNameR);
            BufferedReader lineR = new BufferedReader(fileR);
            FileReader fileS = new FileReader(fileNameS);
            BufferedReader lineS = new BufferedReader(fileS)) {
            String strR = lineR.readLine();
            String strS = lineS.readLine();
            String splitR[] = strR.split("-");
            String splitS[] = strS.split("-");
            int N = splitR.length;
            for(int i = 0; i<N; i++){
                Signature sign = new Signature();
                sign.setR(new BigInteger(splitR[i]));
                sign.setS(new BigInteger(splitS[i]));
                signList.add(sign);
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return signList;
    }

    //signature verification
    public static boolean signVerification(Keys currentKeys, BigInteger hash, Signature sign2Check, Constants currentConstants){
        //first test
        if(sign2Check.getR().compareTo(BigInteger.valueOf(0)) == 1 && sign2Check.getR().compareTo(currentConstants.getQ()) == -1
            && sign2Check.getS().compareTo(BigInteger.valueOf(0)) == 1 && sign2Check.getS().compareTo(currentConstants.getQ()) == -1 ){
            //vars compute
            int M = hash.bitLength();
            int N = currentConstants.getQ().bitLength();
            BigInteger w = sign2Check.getS().modInverse(currentConstants.getQ());
            BigInteger z = hash.shiftRight(Math.max(0,M-N));
            BigInteger u1 = (z.multiply(w)).mod(currentConstants.getQ());
            BigInteger u2 = (sign2Check.getR().multiply(w)).mod(currentConstants.getQ());
            BigInteger v = (((currentConstants.getG().modPow(u1,currentConstants.getP())).multiply(currentKeys.getPubkey().modPow(u2,currentConstants.getP()))).mod(currentConstants.getP())).mod(currentConstants.getQ());
            //second test
            if(v.compareTo(sign2Check.getR()) == 0){
                //System.out.println("Right signature !");
                return true;
            }
        }
        System.out.println("Wrong Signature !");
        return false;
    }

    //signatures from file verification
    public static void signsFromFileVerification(String signFileName, String messageFileName, Keys currentKeys, Constants currentConstants) throws SignatureException {
        try(FileReader receiveMessages = new FileReader(messageFileName);

            BufferedReader buffer = new BufferedReader(receiveMessages)){

            ArrayList<Integer> errorsLine = new ArrayList<Integer>();
            String line;
            ArrayList<Signature> signList = readSignaturesString(signFileName);
            int i = 0;
            while ((line = buffer.readLine()) != null){
                BigInteger hashline = hashComputing("MD5",line);
                if(signVerification(currentKeys, hashline, signList.get(i), currentConstants) == false){
                    errorsLine.add(i+1);
                }
                i++;
            }

            //write signature error's line in a file:
            if(errorsLine != null && errorsLine.size()>0) {
                WriteService.writeErrorSignatureLine(errorsLine);
            }
            else{
                System.out.println("All messages are well-signed!");
            }
        }catch (IOException e){
            e.printStackTrace();
        }
    }

    //signatures from 2 files
    public static void signsFromTwoFilesVerification(String signFileNameR, String signFileNameS, String messageFileName, Keys currentKeys, Constants currentConstants) throws SignatureException {
        try(FileReader receiveMessages = new FileReader(messageFileName);
            BufferedReader buffer = new BufferedReader(receiveMessages)){
            String line;
            ArrayList<Signature> signList = readSignaturesString2(signFileNameR, signFileNameS);
            int i = 0;
            while ((line = buffer.readLine()) != null){
                BigInteger hashline = hashComputing("MD5",line);
                if(signVerification(currentKeys, hashline, signList.get(i), currentConstants) == false){
                    System.out.println("Wrong Signature");
                    throw new SignatureException("One of the signature is wrong"); //How print an exeption ?
                }
                i++;
            }
        }catch (IOException e){
            e.printStackTrace();
        }
    }

    //1000 signatures
    //out: give the time to compute N signatures from the same message
    //unit : nanosecond
    public static long manySignatures(int N, String toSign, Keys currentKeys, Constants currentConstants){
        long start = System.nanoTime();
        for(int i = 0; i<N; i++){
            BigInteger hash = hashComputing("MD5",toSign);
            SecretNumber currentSecret = secretNumGen(currentConstants.getP(),currentConstants.getQ());
            dsaSignature(hash,currentKeys,currentConstants,currentSecret);
        }
        long end = System.nanoTime();
        return end - start;
    }
}
