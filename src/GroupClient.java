/* Implements the GroupClient Interface */

import java.util.ArrayList;
import java.util.List;
import java.io.ObjectInputStream;
import java.security.*;
import javax.crypto.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.util.*;
import java.math.BigInteger;

public class GroupClient extends Client implements GroupClientInterface {

	private Cipher cipher = null;
	private SecretKey[] key_set = null;
	private SecretKey symKey = null;
	private SecretKey hmacKey = null;
	int sessionID = 0;
	
	private static Scanner scan = new Scanner(System.in);
	
	public GroupClient(String name, int port)
	{
		Security.addProvider(new BouncyCastleProvider());
		connect(name, port);
	}
	
	//public static void main(String [] args)
	//{
	//	GroupClient temp = new GroupClient("localhost", 8765);
	//	if(temp.isConnected())
	//		System.out.println("Connected");
	//	else
	//		System.out.println("Not");
	//}
	//this method is ONLY to be used on initialization
	public boolean initialize()
	{
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
		}
		catch(Exception e)
		{
			System.err.println("Error (gc initialize): " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
		return true;
	}
	
	public Key authenticate(Key adminKey,String username) {
		Envelope message = null, response = null;
		try{
			//authenticate
			message = new Envelope("AUTH");
			message.addObject(adminKey);
			message.addObject(username);
			//must encrypt the message
			message = DiffieHellman.addData(message, sessionID++);
			message = DiffieHellman.addHMAC(message, hmacKey);
			message = DiffieHellman.encrypt(cipher, symKey, message);
			output.writeObject(message);
			
			response = (Envelope)input.readObject();
			//must decrypt message
			response = DiffieHellman.decrypt(cipher, symKey, response);
			if(!DiffieHellman.verify(response, sessionID++, hmacKey)) {
				System.out.println("Verification failed. GC");
			}
			if(response.getMessage().equals("DONE"))
			{
				Key servers = (Key)response.getObjContents().get(0);
				return servers;
			}
		}catch(Exception e) {
			e.printStackTrace();
			return null;
		}
		return null;
	}

	 public ArrayList<Object> getToken(String username, Key publicKey, Key privateKey, Key serverKey, Key fServerKey )
	 {
	 	Envelope message = null, response = null;
		try
		{
			ArrayList<Object> tokenAndKeys=new ArrayList<Object>(); //returns [UserToken,HashMap<String.ArrayList<SecretKey>>]
			UserToken token = null;
		 		 	
			//Tell the server to return a token.
			message = new Envelope("GET");	///will need a new case in the server
			message.addObject(username); //Add user name string
			message.addObject(fServerKey);//add the file servers key to be added to the token
			message = DiffieHellman.addData(message, sessionID++);
			message = DiffieHellman.addHMAC(message, hmacKey);
			message = DiffieHellman.encrypt(cipher, symKey, message);
			output.writeObject(message);
		
			//Get the response from the server
			//System.out.println("Waiting for first response");
			response = (Envelope)input.readObject();
			//decrypt
			response = DiffieHellman.decrypt(cipher, symKey, response);
			if(!DiffieHellman.verify(response, sessionID++, hmacKey)) {
				System.out.println("Verification failed. GC");
			}
			//user exists in system if okay
			//System.out.println(response.getMessage());
			message = new Envelope("FAIL");
			if(response.getMessage().equals("OK"))
			{
				System.out.println("got OK");
				//get the challenge
				byte [] c1 = (byte [])response.getObjContents().get(0);
				int selection = 0; 
				Random rand = null;
				byte [] c2 = null;
				int n = 0;
				
				byte[] encryption = null;
				
				encryption = encrypt(c1, privateKey);
				rand = new Random();
				c2 = null;
				n = rand.nextInt(2147483647);
				c2 = BigInteger.valueOf(n).toByteArray();

				output.reset();

				message = new Envelope("RECEIVE");
				message.addObject(encryption);
				message.addObject(c2);
				message = DiffieHellman.addData(message, sessionID++);
				message = DiffieHellman.addHMAC(message, hmacKey);
				message = DiffieHellman.encrypt(cipher, symKey, message);
				//System.out.println(message.getMessage());
				output.writeObject(message);
				
				//Successful response
				response = (Envelope)input.readObject();
				response = DiffieHellman.decrypt(cipher, symKey, response);
				if(!DiffieHellman.verify(response, sessionID++, hmacKey)) {
					System.out.println("Verification failed. GC");
				}
				//System.out.println(response.getMessage());
				if(response.getMessage().equals("DONE"))
				{
					//System.out.println("got DONE");
					//If there is a token in the Envelope, return it 
					ArrayList<Object> temp = null;
					temp = response.getObjContents();
					//System.out.println("TOken received");
					
					//System.out.println("Token should be sent back");
					token = (UserToken)temp.get(0);
					byte[] cipher = (byte[])temp.get(1);			//get the encrypted challenge
					if(decrypt(cipher, serverKey, c2))			//decrypt the challenge to make sure token came from server
					{
						tokenAndKeys.add(token);
						tokenAndKeys.add((HashMap<String,ArrayList<SecretKey>>)temp.get(2));
						return tokenAndKeys;
					}
					else
					{
						System.out.println("Unable to authenticate server");
						return null;
					}
					
				}
				
			}
        }
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
		return null;
    }
			
	 
	 private byte[] encrypt(byte[] c1,Key privateKey)
	 {
		Security.addProvider(new BouncyCastleProvider());
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
		
		///////////////start encryption using users private key
		try{
			cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		}
		catch(InvalidKeyException e)
		{
			System.out.println("Invalid key RSA encryption");
		}
		
		//convert input to byte array
		//byte [] text = input.getBytes(Charset.forName("UTF-8"));
		
		//print out text as bytes in hex
		byte [] cipherText = null;
		//System.out.println("Byte input to RSA: " + Utils.toHex(c1));
		
		try{	
			cipherText = cipher.doFinal(c1);
		}
		catch(IllegalBlockSizeException e)
		{
			System.out.println("IllegalBlockSizeException RSA encryption");
		}
		catch(BadPaddingException e)
		{
			System.out.println("BadPaddingException RSA encryption");
		}
		
		//print cipher output
		//System.out.println("RSA Cipher output: " + Utils.toHex(cipherText));
		
		return cipherText;
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
	 
	 private byte[] decryptSig(byte [] cipherText, Key serverKey)
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
		return plainText;
		
	 }
		
	 
	 public boolean createUser(String username, UserToken token, Key publicKey)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to create a user
				message = new Envelope("CUSER");
				message.addObject(username); //Add user name string
				message.addObject(token); //Add the requester's token
				message.addObject(publicKey);	//add the new users public key
				message = DiffieHellman.addData(message, sessionID++);
				message = DiffieHellman.addHMAC(message, hmacKey);
				message = DiffieHellman.encrypt(cipher, symKey, message);
				output.writeObject(message);
			
				response = (Envelope)input.readObject();
				response = DiffieHellman.decrypt(cipher, symKey, response);
				if(!DiffieHellman.verify(response, sessionID++, hmacKey)) {
					System.out.println("Verification failed. GC");
				}
				
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean deleteUser(String username, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
			 
				//Tell the server to delete a user
				message = new Envelope("DUSER");
				message.addObject(username); //Add user name
				message.addObject(token);  //Add requester's token
				message = DiffieHellman.addData(message, sessionID++);
				message = DiffieHellman.addHMAC(message, hmacKey);
				message = DiffieHellman.encrypt(cipher, symKey, message);
				output.writeObject(message);
			
				response = (Envelope)input.readObject();
				response = DiffieHellman.decrypt(cipher, symKey, response);
				if(!DiffieHellman.verify(response, sessionID++, hmacKey)) {
					System.out.println("Verification failed. GC");
				}
				
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean createGroup(String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to create a group
				message = new Envelope("CGROUP");
				message.addObject(groupname); //Add the group name string
				message.addObject(token); //Add the requester's token
				message = DiffieHellman.addData(message, sessionID++);
				message = DiffieHellman.addHMAC(message, hmacKey);
				message = DiffieHellman.encrypt(cipher, symKey, message);
				output.writeObject(message); 
			
				response = (Envelope)input.readObject();
				response = DiffieHellman.decrypt(cipher, symKey, response);
				if(!DiffieHellman.verify(response, sessionID++, hmacKey)) {
					System.out.println("Verification failed. GC");
				}
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean deleteGroup(String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to delete a group
				message = new Envelope("DGROUP");
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token
				message = DiffieHellman.addData(message, sessionID++);
				message = DiffieHellman.addHMAC(message, hmacKey);
				message = DiffieHellman.encrypt(cipher, symKey, message);
				output.writeObject(message); 
			
				response = (Envelope)input.readObject();
				response = DiffieHellman.decrypt(cipher, symKey, response);
				if(!DiffieHellman.verify(response, sessionID++, hmacKey)) {
					System.out.println("Verification failed. GC");
				}
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 @SuppressWarnings("unchecked")
	public List<String> listMembers(String group, UserToken token)
	 {
		 try
		 {
			 Envelope message = null, response = null;
			 //Tell the server to return the member list
			 message = new Envelope("LMEMBERS");
			 message.addObject(group); //Add group name string
			 message.addObject(token); //Add requester's token
			 message = DiffieHellman.addData(message, sessionID++);
			message = DiffieHellman.addHMAC(message, hmacKey);
			 message = DiffieHellman.encrypt(cipher, symKey, message);
			 output.writeObject(message); 
			 
			 response = (Envelope)input.readObject();
			 response = DiffieHellman.decrypt(cipher, symKey, response);
			 if(!DiffieHellman.verify(response, sessionID++, hmacKey)) {
				System.out.println("Verification failed. GC");
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
	 
	 public boolean addUserToGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to add a user to the group
				message = new Envelope("AUSERTOGROUP");
				message.addObject(username); //Add user name string
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token
				message = DiffieHellman.addData(message, sessionID++);
				message = DiffieHellman.addHMAC(message, hmacKey);
				message = DiffieHellman.encrypt(cipher, symKey, message);
				output.writeObject(message); 
			
				response = (Envelope)input.readObject();
				response = DiffieHellman.decrypt(cipher, symKey, response);
				if(!DiffieHellman.verify(response, sessionID++, hmacKey)) {
					System.out.println("Verification failed. GC");
				}
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean deleteUserFromGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to remove a user from the group
				message = new Envelope("RUSERFROMGROUP");
				message.addObject(username); //Add user name string
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token
				message = DiffieHellman.addData(message, sessionID++);
				message = DiffieHellman.addHMAC(message, hmacKey);
				message = DiffieHellman.encrypt(cipher, symKey, message);
				output.writeObject(message);
			
				response = (Envelope)input.readObject();
				response = DiffieHellman.decrypt(cipher, symKey, response);
				if(!DiffieHellman.verify(response, sessionID++, hmacKey)) {
					System.out.println("Verification failed. GC");
				}
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

}
