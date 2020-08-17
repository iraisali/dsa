package utils;

import fr.irmar.Keys;
import fr.irmar.SecretNumber;
import fr.irmar.Signature;
import fr.irmar.SignatureException;
import org.jetbrains.annotations.NotNull;

import java.io.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Random;

//fonctions "générales"
public class Tools {

    //entree: longueur de l'entier en bits
    //sortie: BigInt généré aléatoirement
    public static BigInteger bigRandGen(int lenth){
        Random rnd = new Random();
        BigInteger n = new BigInteger(lenth,rnd);
        return n;
    }

    //Stocker la liste de signature obtenue
    public static void saveSign(ArrayList<Signature> currentSign, String fileOutName){
        BigInteger zero = BigInteger.valueOf(0);
        try(FileOutputStream fileOut = new FileOutputStream(fileOutName);
            ObjectOutputStream buffer = new ObjectOutputStream(fileOut)) //ce mode de déclaration permet de close() automatiquement
        {
            buffer.writeObject(currentSign);
        }catch (IOException e){
            e.printStackTrace();
        }
    }

    //generateur de cle cf appendice B1 page 47
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

    //Signer les messages issues d'un fichier (norme : une ligne = 1 message)
    //in: file name
    //out: arrayList with all signatures
    public static ArrayList signMessage(String sourcename, Keys currentKeys, Constants currentConstants, SecretNumber currentSecretNum){
        ArrayList<Signature>  signatureList = new ArrayList<Signature>();

        try (FileReader reader = new FileReader(sourcename);
             BufferedReader buffer = new BufferedReader(reader)){
            String line;
            while ((line = buffer.readLine()) != null){

                //BigInteger hashline = hashComputing("sha-1",line);
                BigInteger hashline = hashComputing("MD5",line);
                currentSecretNum = secretNumGen(currentConstants.getP(),currentConstants.getQ());
                signatureList.add(dsaSignature(hashline,currentKeys,currentConstants,currentSecretNum));
            }

        } catch (IOException e) {
            e.printStackTrace();
        }

        return signatureList;
    }

    //Calculer valeur de hashage
    //in: - nom de la méthode de hashage (Str)
    // - Message (Str)
    //out: hash sous forme d'un BigInt
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
            System.out.println("puissance nulle.");
            System.exit(42);
        }

        //N est la longueur de q (en bits)
        //bitLength OU bitCount ???
        int M = currentHash.bitLength();
        int N = currentConstants.getQ().bitLength(); // il n'y a pas besoin de currentConstantsidérer le min comme dans la doc (?)

        BigInteger z;
        z = currentHash.shiftRight(Math.max(0,M-N)); //FIXME: s'assure que c'est equivalent a prendre les min(M,N) bits les plus a gauche
        currentSignature.setS(((currentSecret.getInvSecret()).multiply(z.add(currentKeys.getPrivkey().multiply(currentSignature.getR())))).mod(currentConstants.getQ()));
        return currentSignature;
    }

    //lecture des signatures
    public static ArrayList<Signature> readSignatures(String fileName) {
        ArrayList<Signature> sign= new ArrayList<Signature>();
        try(FileInputStream file = new FileInputStream(fileName);
            ObjectInputStream obj = new ObjectInputStream(file)){// No buffer is required because ObjectInputStream is automaticaly buffered.

            sign = (ArrayList<Signature>) obj.readObject();
        }
        catch(IOException | ClassNotFoundException e){
           e.printStackTrace();
        }
        return sign;
    }

    //signature verification
    public static boolean signVerification(Keys currentKeys, BigInteger hash, Signature sign2Check, Constants currentConstants){
        //first test
        if(sign2Check.getR().compareTo(BigInteger.valueOf(0)) == 1 && sign2Check.getR().compareTo(currentConstants.getQ()) == -1
            && sign2Check.getS().compareTo(BigInteger.valueOf(0)) == 1 && sign2Check.getS().compareTo(currentConstants.getQ()) == -1 ){
            //vars compute
            int M = hash.bitLength();
            int N = currentConstants.getQ().bitLength(); // il n'y a pas besoin de currentConstantsidérer le min comme dans la doc (?)
            BigInteger w = sign2Check.getS().modInverse(currentConstants.getQ());
            BigInteger z = hash.shiftRight(Math.max(0,M-N));
            BigInteger u1 = (z.multiply(w)).mod(currentConstants.getQ());
            BigInteger u2 = (sign2Check.getR().multiply(w)).mod(currentConstants.getQ());
            BigInteger v = (((currentConstants.getG().modPow(u1,currentConstants.getP())).multiply(currentKeys.getPubkey().modPow(u2,currentConstants.getP()))).mod(currentConstants.getP())).mod(currentConstants.getQ());
            //second test
            if(v.compareTo(sign2Check.getR()) == 0){
                System.out.println("Right signature !");
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
            String line;
            ArrayList<Signature> signList = readSignatures(signFileName);
            int i = 0; //Je pense que c'est un peu merdique de faire ca comme ca
            while ((line = buffer.readLine()) != null){
                //System.out.println(line);
                BigInteger hashline = hashComputing("MD5",line);
                if(signVerification(currentKeys, hashline, signList.get(i), currentConstants) == false){
                    System.out.println("signature fausse.");
                    throw new SignatureException("L'une des signatures est fausse."); //comment afficher exception ?
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
    public static long manySignatures(int N, String toSign, Keys currentKeys, Constants currentConstants, SecretNumber currentSecret){
        BigInteger hash = hashComputing("sha-1",toSign); //le calcul du hash doit il faire partie du temps de calcul ?
        long start = System.nanoTime();
        for(int i = 0; i<N; i++){
            dsaSignature(hash,currentKeys,currentConstants,currentSecret);
        }
        long end = System.nanoTime();
        return end - start;
    }
}
