/* FileClient provides all the client functionality regarding the file server */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import javax.crypto.*;
import java.security.Security;
import java.security.*;
import java.security.PublicKey;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import java.security.KeyPair;
import java.math.BigInteger;
import java.util.*;


import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class FileClient extends Client implements FileClientInterface {

	private Cipher cipher;
	private SecretKey[] key_set;
	private SecretKey symKey;
	private SecretKey hmacKey;
	int sessionID = 0;

	public FileClient(String name, int port)
	{
		Security.addProvider(new BouncyCastleProvider());
		connect(name, port);
	}

	public boolean initialize() {
		Envelope message = null, response = null;
		try
		{
			//must establish a secure channel
			PublicKey serverPublicKey = null;
			KeyPair clientKP = DiffieHellman.newKeyPair();
			KeyAgreement clientAgreement = DiffieHellman.newKeyAgreement(clientKP.getPrivate());

			message = new Envelope("INIT");
			message.addObject(clientKP.getPublic());
			output.writeObject(message);

			response = (Envelope)input.readObject();
			if(response.getMessage().equals("DONE")) {
				serverPublicKey = (PublicKey)response.getObjContents().get(0);
			}

			//create the shared secret
			key_set = DiffieHellman.newSecretKeySet(clientAgreement, serverPublicKey);
			symKey = key_set[0];
			hmacKey = key_set[1];
			//and the cipher
			cipher = DiffieHellman.newCipher();
			return true;
		}catch(Exception e) {
			System.err.println("Error (fc initialize): " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public Key authenticate(Key gsPublicKey) {
		Envelope message = null, response = null;
		try{
			//authenticate
			message = new Envelope("AUTH");
			message.addObject(gsPublicKey);
			message = DiffieHellman.addData(message, sessionID++);
			message = DiffieHellman.addHMAC(message, hmacKey);
			message = DiffieHellman.encrypt(cipher, symKey, message);
			output.writeObject(message);

			response = (Envelope)input.readObject();
			response = DiffieHellman.decrypt(cipher, symKey, response);
			if(!DiffieHellman.verify(response, sessionID++, hmacKey)) {
				System.out.println("Verification failed. FC");
			}
			if(response.getMessage().equals("OK"))
			{	
				return (Key)response.getObjContents().get(0);
			}
			else
			{
				return null;
			}
		}catch(Exception e) {
			System.out.println("Unable to receive FileServer public key");
			e.printStackTrace();
			return null;
		}
	}
	
	public boolean checkPublicKey(Key fileServerPublicKey)
	{
		Envelope message = null, response = null;
		try{
			
			Random rand = null;
			byte [] c2 = null;
			int n = 0;	
			
			//generate a challenge for the file server to encrypt
			rand = new Random();
			n = rand.nextInt(2147483647);
			c2 = BigInteger.valueOf(n).toByteArray();
			
			message = new Envelope("CHECK_PUB");
			message.addObject(c2);
			message = DiffieHellman.addData(message, sessionID++);
			message = DiffieHellman.addHMAC(message, hmacKey);
			message = DiffieHellman.encrypt(cipher, symKey, message);
			output.writeObject(message);
			
			response = (Envelope)input.readObject();
			response = DiffieHellman.decrypt(cipher, symKey, response);
			if(!DiffieHellman.verify(response, sessionID++, hmacKey)) {
				System.out.println("Verification failed. FC");
			}
			if(response.getMessage().equals("FENCRYP"))
			{
				if(response.getObjContents().size() <50)
				{
					byte [] cipher = (byte [])response.getObjContents().get(0);
					if(decrypt(cipher, fileServerPublicKey, c2))
					{
						return true;
					}
					else
					{
						return false;
					}
				}
			}
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
		return false;
	}	

	 private boolean decrypt(byte [] cipherText, Key serverKey, byte[] num)
	 {	
		Cipher cipher = null;
		
		try{
			cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
		}
		catch(NoSuchAlgorithmException e)
		{
			System.out.println("Algoirthm does not exist for cipher RSA");
		}
		catch(NoSuchProviderException e)
		{
			System.out.println("No provider for cipher RSA");
		}
		catch(NoSuchPaddingException e)
		{
			System.out.println("Padding exception RSA");
		}
		
		try{
			cipher.init(Cipher.DECRYPT_MODE, serverKey);
		}
		catch(InvalidKeyException e)
		{
			System.out.println("InvalidKeyException RSA decryption");
		}
		
		byte [] plainText = null;
		try{
			plainText = cipher.doFinal(cipherText);
		}
		catch(IllegalBlockSizeException e)
		{
			System.out.println("IllegalBlockSizeException RSA decryption");
		}
		catch(BadPaddingException e)
		{
			System.out.println("BadPaddingException RSA decryption");
		}
		
		int resp = new BigInteger(plainText).intValue();
		int key = new BigInteger(plainText).intValue();
		
		if(resp == key)
		{
			return true;
		}
		else
		{
			return false;
		}
	 }	
			

	public boolean delete(String filename, UserToken token) {
		String remotePath;
		if (filename.charAt(0)=='/') {
			remotePath = filename.substring(1);
		}
		else {
			remotePath = filename;
		}
		Envelope env = new Envelope("DELETEF"); //Success
	    env.addObject(remotePath);
	    env.addObject(token);
	    env = DiffieHellman.addData(env, sessionID++);
		env = DiffieHellman.addHMAC(env, hmacKey);
	    env = DiffieHellman.encrypt(cipher, symKey, env);
	    try {
			output.writeObject(env);
		    env = (Envelope)input.readObject();
		    env = DiffieHellman.decrypt(cipher, symKey, env);
		    if(!DiffieHellman.verify(env, sessionID++, hmacKey)) {
				System.out.println("Verification failed. FC");
			}
		    
			if (env.getMessage().compareTo("OK")==0) {
				System.out.printf("File %s deleted successfully\n", filename);				
			}
			else {
				System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
				return false;
			}			
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		}
	    	
		return true;
	}

	public ArrayList<Object> download(String sourceFile, String destFile, UserToken token) {
				if (sourceFile.charAt(0)=='/') {
					sourceFile = sourceFile.substring(1);
				}
				ArrayList<Object> temp=new ArrayList<Object>(); //will return key version and encrypted key version as well
				File file = new File(destFile);
			    try {
			    				
				
				    if (!file.exists()) {
				    	file.createNewFile();
					    FileOutputStream fos = new FileOutputStream(file);
					    Envelope env = new Envelope("DOWNLOADF"); //Success
					    env.addObject(sourceFile);
					    env.addObject(token);
					    env = DiffieHellman.addData(env, sessionID++);
						env = DiffieHellman.addHMAC(env, hmacKey);
					    env = DiffieHellman.encrypt(cipher, symKey, env);
					    output.writeObject(env); 
						
					    env = (Envelope)input.readObject();
					    env = DiffieHellman.decrypt(cipher, symKey, env);
					    if(!DiffieHellman.verify(env, sessionID++, hmacKey)) {
							System.out.println("Verification failed. FC");
						}
					    
						while (env.getMessage().compareTo("CHUNK")==0) { 
								fos.write((byte[])env.getObjContents().get(0), 0, (Integer)env.getObjContents().get(1));
								System.out.printf(".");
								env = new Envelope("DOWNLOADF"); //Success
								env = DiffieHellman.addData(env, sessionID++);
								env = DiffieHellman.addHMAC(env, hmacKey);
								env = DiffieHellman.encrypt(cipher, symKey, env);
								output.writeObject(env);
								env = (Envelope)input.readObject();	
								env = DiffieHellman.decrypt(cipher, symKey, env);
								if(!DiffieHellman.verify(env, sessionID++, hmacKey)) {
									System.out.println("Verification failed. FC");
								}								
						}										
						fos.close();
						
					    if(env.getMessage().compareTo("EOF")==0) {
					    	 fos.close();
								System.out.printf("\nTransfer successful file %s\n", sourceFile);
								temp.add(env.getObjContents().get(0)); //int version
								temp.add(env.getObjContents().get(1)); //encrypted byte[] of int 
								temp.add(env.getObjContents().get(2)); //IV
								temp.add(env.getObjContents().get(3)); //name of group
								env = new Envelope("OK"); //Success
								env = DiffieHellman.addData(env, sessionID++);
								env = DiffieHellman.addHMAC(env, hmacKey);
								env = DiffieHellman.encrypt(cipher, symKey, env);
								output.writeObject(env);
						}
						else {
								System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
								file.delete();
								return null;								
						}
				    }    
					 
				    else {
						System.out.printf("Error couldn't create file %s\n", destFile);
						return null;
				    }
								
			
			    } catch (IOException e1) {
			    	
			    	System.out.printf("Error couldn't create file %s\n", destFile);
			    	return null;
			    
					
				}
			    catch (ClassNotFoundException e1) {
					e1.printStackTrace();
				}
				 return temp;
	}

	@SuppressWarnings("unchecked")
	public List<String> listFiles(UserToken token) {
		 try
		 {
			 Envelope message = null, response = null;
			 //Tell the server to return the member list
			 message = new Envelope("LFILES");
			 message.addObject(token); //Add requester's token
			message = DiffieHellman.addData(message, sessionID++);
			message = DiffieHellman.addHMAC(message, hmacKey);
			 message = DiffieHellman.encrypt(cipher, symKey, message);
			 output.writeObject(message); 
			 
			response = (Envelope)input.readObject();
			response = DiffieHellman.decrypt(cipher, symKey, response);
			if(!DiffieHellman.verify(response, sessionID++, hmacKey)) {
				System.out.println("Verification failed. FC");
			}
			 
			 //If server indicates success, return the member list
			 if(response.getMessage().equals("OK"))
			 { 
				return (List<String>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
			 }
				
			 return null;
			 
		 }
		 catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
			}
	}

	public boolean upload(String sourceFile, String destFile, String group, 
			UserToken token, int version,byte[] encrVers,byte[] initVector) { 
			
		if (destFile.charAt(0)!='/') {
			 destFile = "/" + destFile;
		 }
		
		try
		 {
			 
			 Envelope message = null, env = null;
			 //Tell the server to return the member list
			 message = new Envelope("UPLOADF");
			 message.addObject(destFile);
			 message.addObject(group);
			 message.addObject(token); //Add requester's token
			 message.addObject(version);
			 message.addObject(encrVers);
			 message.addObject(initVector);
			 message = DiffieHellman.addData(message, sessionID++);
			message = DiffieHellman.addHMAC(message, hmacKey);
			 message = DiffieHellman.encrypt(cipher, symKey, message);
			 output.writeObject(message);
			
			 
			FileInputStream fis = new FileInputStream(sourceFile);
			 
			env = (Envelope)input.readObject();
			env = DiffieHellman.decrypt(cipher, symKey, env);
			if(!DiffieHellman.verify(env, sessionID++, hmacKey)) {
				System.out.println("Verification failed. FC");
			}
			 
			//If server indicates success, return the member list
			if(env.getMessage().equals("READY"))
			{ 
				System.out.printf("Meta data upload successful\n");
			}
			 else {
				
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }
			 
		 	
			 do {
				 byte[] buf = new byte[4096];
				 	if (env.getMessage().compareTo("READY")!=0) {
				 		System.out.printf("Server error: %s\n", env.getMessage());
						message = new Envelope("FAIL");
						message = DiffieHellman.addData(message, sessionID++);
						message = DiffieHellman.addHMAC(message, hmacKey);
						message = DiffieHellman.encrypt(cipher, symKey, message);
						output.writeObject(message);
						
						env = (Envelope)input.readObject();//just to clear the buffer
						env = DiffieHellman.decrypt(cipher, symKey, env);
						if(!DiffieHellman.verify(env, sessionID++, hmacKey)) {
							System.out.println("Verification failed. FC");
						}
				 		return false;
				 	}
				 	message = new Envelope("CHUNK");
					int n = fis.read(buf); //can throw an IOException
					if (n > 0) {
						System.out.printf(".");
					} else if (n < 0) {
						System.out.println("Read error");
						return false;
					}
					
					message.addObject(buf);
					message.addObject(new Integer(n));
					message = DiffieHellman.addData(message, sessionID++);
					message = DiffieHellman.addHMAC(message, hmacKey);
					message = DiffieHellman.encrypt(cipher, symKey, message);
					output.writeObject(message);
					
					
					env = (Envelope)input.readObject();
					env = DiffieHellman.decrypt(cipher, symKey, env);
					if(!DiffieHellman.verify(env, sessionID++, hmacKey)) {
						System.out.println("Verification failed. FC");
					}
					
										
			 }
			 while (fis.available()>0);		 
					 
			 //If server indicates success, return the member list
			 if(env.getMessage().compareTo("READY")==0)
			 { 
				
				message = new Envelope("EOF");
				message = DiffieHellman.addData(message, sessionID++);
				message = DiffieHellman.addHMAC(message, hmacKey);
				message = DiffieHellman.encrypt(cipher, symKey, message);
				output.writeObject(message);
				
				env = (Envelope)input.readObject();
				env = DiffieHellman.decrypt(cipher, symKey, env);
				if(!DiffieHellman.verify(env, sessionID++, hmacKey)) {
					System.out.println("Verification failed. FC");
				}
				if(env.getMessage().compareTo("OK")==0) {
					System.out.printf("\nFile data upload successful\n");
				}
				else {
					
					 System.out.printf("\nUpload failed: %s\n", env.getMessage());
					 return false;
				 }
				
			}
			 else {
				
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }
			 
		 }catch(Exception e1)
			{
				System.err.println("Error: " + e1.getMessage());
				e1.printStackTrace(System.err);
				return false;
				}
		 return true;
	}

}

