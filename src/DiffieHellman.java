import java.math.BigInteger;
import java.util.Arrays;
import java.util.ArrayList;
import java.sql.Timestamp;

import java.security.Security;
import java.security.SecureRandom;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyPairGenerator;
import java.security.KeyFactory;
import java.security.MessageDigest;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.SealedObject;
//import javax.crypto.spec.DHPublicKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class DiffieHellman {

	//static values for p and g
	private static BigInteger p = new BigInteger("20264306993273764606235406482685578230489331724797110404673254604229576460957513082830537625482564399446082680775585896725903437357246069113733173285440655185000641670238728919461329145702796899103975865677459854701616044119071983911424507453003800697578222941557469100073612446982356228315073334127501303763693698928574561164836269690690435583851688095640085837827073102836180249232298379047158727735196426220632542270250782228757422095847709397395769109132436658743351685113117217648410317270373646602729317665779050077146479383873993154944301955587915420912094185916529844764843946352701611190479163108704312587377");
	private static BigInteger g = BigInteger.valueOf(2);
	private static String bad_str_prefix = "[B@";

	/**
	 * Creates a new key pair using static p and g
	**/
	public static KeyPair newKeyPair() {
		try {
			// new kp generator
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");
		    DHParameterSpec paramSpec = new DHParameterSpec(p, g);
		    keyGen.initialize(paramSpec);
		    // gen key pair
		    KeyPair keyPair = keyGen.generateKeyPair();
		    return keyPair;
		} catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}

	/**
	 * Generates a key agreement based on local private key 
	**/
	public static KeyAgreement newKeyAgreement(PrivateKey localPrivateKey) {
		try {
			KeyAgreement agreement = KeyAgreement.getInstance("DH","BC");
			agreement.init(localPrivateKey);
			return agreement;
		}catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}

	/**
	 * Computes the secret key using agreement and remote public key
	**/
	public static SecretKey[] newSecretKeySet(KeyAgreement agreement, PublicKey remotePublicKey) {
		try {
			//first need to doPhase on key agreement
			agreement.doPhase(remotePublicKey, true);
			byte[] secret = agreement.generateSecret();
			//we will be using a 256 bit hash of the secret
			MessageDigest hash = MessageDigest.getInstance("SHA-512", "BC");
			byte[] hashedSecret = hash.digest(secret);
			//now we can turn this into a proper AES and HMAC key
			byte[] aes_bytes = Arrays.copyOfRange(hashedSecret, 0, 32);
			byte[] hmac_bytes = Arrays.copyOfRange(hashedSecret, 32, 64);
			SecretKey aes_key = new SecretKeySpec(aes_bytes, "AES");
			SecretKey hmac_key = new SecretKeySpec(hmac_bytes, "AES");
			SecretKey[] keys = {aes_key, hmac_key};
			//System.out.println(Utils.toHex(keys[1].getEncoded()));
			return keys;
		}catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}

	

	/**
	 * Generate and return an AES 256 cipher
	**/
	public static Cipher newCipher() {
		try {
			return Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
		}catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}

	/**
	 * Encrypt a message
	**/ 
	public static Envelope encrypt(Cipher cipher, SecretKey key, Envelope input) {
		try {
			//gen a new iv
			byte[] iv = new BigInteger(128, new SecureRandom()).toByteArray();
			if(iv.length>16) {
				iv = java.util.Arrays.copyOfRange(iv, 1, 17);
			}
			//initialize cipher
			cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
			//encrypt
			SealedObject sealedEnvelope = new SealedObject(input, cipher);
			Envelope ret = new Envelope("SEALED");
			ret.addObject(iv);
			ret.addObject(sealedEnvelope);
			return ret;
		}catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}

	/**
	 * Decrypt a message
	 * return an Envelope
	**/ 
	public static Envelope decrypt(Cipher cipher, SecretKey key, Envelope sealedEnvelope) {
		try {
			byte[] iv = (byte[])sealedEnvelope.getObjContents().get(0);
			SealedObject obj = (SealedObject)sealedEnvelope.getObjContents().get(1);
			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
			Envelope msg = (Envelope)obj.getObject(key);
			return msg;
		}catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}

	//test with main
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		System.out.println("p = "+p);
		System.out.println("g = "+g);

		KeyPair bobKP = newKeyPair();
		KeyPair aliceKP = newKeyPair();

		KeyAgreement bobKA = newKeyAgreement(bobKP.getPrivate());
		KeyAgreement aliceKA = newKeyAgreement(aliceKP.getPrivate());

		SecretKey[] bobSK = newSecretKeySet(bobKA, aliceKP.getPublic());
		SecretKey[] aliceSK = newSecretKeySet(aliceKA, bobKP.getPublic());

		//System.out.println(java.util.Arrays.equals(bobSK.getEncoded(), aliceSK.getEncoded()));
	}

	public static Envelope addData(Envelope msg, int sessionID) {
		//add timestamp
		Timestamp time = new Timestamp(java.lang.System.currentTimeMillis());
		msg.addObject(time);
		//add session ID
		Integer i = new Integer(sessionID);
		msg.addObject(i);
		return msg;
	}

	public static byte[] getHMAC(Envelope msg, SecretKey hmac_key) {
		try{
			//get everything in envelope as string
			String msgString = "";
			ArrayList<Object> objs = msg.getObjContents();
			for(int i=0;i<objs.size();i++) {
				String objString = objs.get(i).toString();
				if(!objString.startsWith(bad_str_prefix)) {
					msgString += objString;
				}
			}
			
			//concat hmac key
			msgString += Utils.toHex(hmac_key.getEncoded());
			//print
			//System.out.println(msgString);
			//hash (sha256)
			MessageDigest hash = MessageDigest.getInstance("SHA-256", "BC");
			byte[] msgBytes = msgString.getBytes();
			byte[] hmac = hash.digest(msgBytes);
			return hmac;
		}catch(Exception e) {
			System.err.println("Error (gethmac) : " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}

	public static Envelope addHMAC(Envelope msg, SecretKey hmac_key) {
		byte[] hmac = getHMAC(msg, hmac_key);

		//add hash to msg
		msg.addObject(hmac);
		return msg;
	}

	public static boolean verify(Envelope msg, int expectedID, SecretKey hmac_key) {
		try{
			boolean ret = true;
			ArrayList<Object> objs = msg.getObjContents();
			//get timestamp 
			Timestamp msg_time = (Timestamp)objs.get(objs.size() - 3);
			Timestamp cur_time = new Timestamp(java.lang.System.currentTimeMillis());
			//check within 5 minutes of time
			int five_min = 5 * 60 * 1000;
			if(cur_time.before(msg_time)) {
				ret = false;
				System.out.println("Timestamp is from the future!");
			}
			if(cur_time.getTime() - msg_time.getTime() > five_min) {
				ret = false;
				System.out.println("Timestamp > 5 minutes old!");
			}

			//get id, check == expected
			Integer msg_id = (Integer)objs.get(objs.size() - 2);
			if(msg_id != expectedID) {
				System.out.println("SessionID's do NOT match!");
				ret = false;
			}
			//get hmac
			byte[] msg_hmac = (byte[])objs.get(objs.size() - 1);
			//compute hmac
			String msgString = "";
			for(int i=0;i<objs.size()-1;i++) {
				String objString = objs.get(i).toString();
				if(!objString.startsWith(bad_str_prefix)) {
					msgString += objString;
				}
			}
			msgString += Utils.toHex(hmac_key.getEncoded());
			MessageDigest hash = MessageDigest.getInstance("SHA-256", "BC");
			byte[] msgBytes = msgString.getBytes();
			byte[] hmac = hash.digest(msgBytes);
			//check same
			if(!java.util.Arrays.equals(msg_hmac, hmac)) {
				System.out.println("HMACs do NOT match!");
				//System.out.println(Utils.toHex(msg_hmac));
				//System.out.println(Utils.toHex(computed_hmac));
				ret = false;
			}
			return ret;
		}catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}
}