
import java.util.*;
import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
//Matt Stropkey


public class UserKeys implements java.io.Serializable {

		private static final long serialVersionUID = 7600343803563417313L;
		private Hashtable<String, UserKeyHolder> list = new Hashtable<String, UserKeyHolder>();
		
		//constructor
		public UserKeys()
		{
			
		}
		
		//add a new user to the list, generate a pair of keys for them
		public synchronized boolean addUser(String username, Key serverKey, Key fileServerKey)
		{
			//make sure user does not already exist
			if(!checkUser(username))
			{
				KeyPair userKeys = generateKeys();
				UserKeyHolder userK = new UserKeyHolder(userKeys.getPrivate(), userKeys.getPublic(), serverKey, fileServerKey);
				list.put(username, userK);
				return true;
			}
			return false;
		}
		
		//used to remove a user from the key list
		public synchronized boolean removeUser(String username)
		{
			try{
				list.remove(username);
				return true;
			}catch(Exception e){
				e.printStackTrace();
				return false;
			}
		}
		
		//used to check if a user is already existing
		public synchronized boolean checkUser(String username)
		{
			if(list.containsKey(username))
			{
				return true;
			}
			else
			{
				return false;
			}
		}
		
		//get the public key of a user
		public synchronized Key getPublicKey(String username)
		{
			if(checkUser(username))
				return list.get(username).getPublic();
			else
				return null;
		}
		
		//get the private key of a user
		public synchronized Key getPrivateKey(String username)
		{
			if(checkUser(username))
				return list.get(username).getPrivate();
			else
				return null;
		}
		
		public synchronized Key getServerKey(String username)
		{
			if(checkUser(username))
				return list.get(username).getServerKey();
			else
				return null;
		}
		
		public synchronized Key getFileServerKey(String username)
		{
			if(checkUser(username))
				return list.get(username).getFileServerKey();
			else
				return null;
		}
		
		//get the group server key that a user has stored
		public synchronized void removeKey(String username)
		{
			if(checkUser(username))
				list.remove(username);	
		}
		
		//change a users public key
		public synchronized void changePubKey(String username, Key pubKey)
		{
			if(checkUser(username))
				list.get(username).updatePubKey(pubKey);
		}
		
		//change a users private key
		public synchronized void changePrivKey(String username, Key privKey)
		{
			if(checkUser(username))
				list.get(username).updatePrivKey(privKey);
		}
		
		//chage a users group server key
		public synchronized void changeServerKey(String username, Key servKey)
		{
			if(checkUser(username))
				list.get(username).updateServerKey(servKey);
		}
		
		public synchronized void changeFileKey(String username, Key fileKey)
		{
			if(checkUser(username))
				list.get(username).updateFileServerKey(fileKey);
		}
		
		//generate a key pair
		private KeyPair generateKeys()
		{
			Security.addProvider(new BouncyCastleProvider());
			KeyPairGenerator key = null;
			KeyPair keys = null;
			Key privateKey = null;
			Key publicKey = null;
			//generate keys
			try{
				key = KeyPairGenerator.getInstance("RSA", "BC");		//generate a key pair for RSA using bouncycastle
				key.initialize(2048);									//initialize the key size to 2048
				keys = key.generateKeyPair();
				privateKey = keys.getPrivate();
				publicKey = keys.getPublic();
				//can be used to print out the key pairs
				//System.out.println("\n\nRSA Public key: " + Utils.toHex(publicKey.getEncoded()));
				//System.out.println("\n\ndRSA Private key: " + Utils.toHex(privateKey.getEncoded()));
			}
			catch(NoSuchAlgorithmException e)
			{
				System.out.println("No algorithm for RSA keys");
			}
			catch(NoSuchProviderException e)
			{
				System.out.println("No such provider for user key");
			}
			return keys;
		}
		
	class UserKeyHolder implements java.io.Serializable {
		
		private static final long serialVersionUID = -6699986456399821590L;
		private Key pKey;
		private Key pubKey;
		private Key serverKey;
		private Key fileServerKey;
		
		public UserKeyHolder(Key key1, Key key2, Key key3, Key fKey)
		{
			pKey = key1;
			pubKey = key2;
			serverKey = key3;
			fileServerKey = fKey;
		}
		
		
		public Key getPublic()
		{
			return pubKey;
		}
		
		public Key getPrivate()
		{
			return pKey;
		}
		
		public void updatePubKey(Key key2)
		{
			pubKey = key2;
		}
		
		public void updatePrivKey(Key key1)
		{
			pKey = key1;
		}
		
		public Key getServerKey()
		{
			return serverKey;
		}
		
		public void updateServerKey(Key key3)
		{
			serverKey = key3;
		}
		
		public void updateFileServerKey(Key fKey)
		{
			fileServerKey = fKey;
		}
		
		public Key getFileServerKey()
		{
			return fileServerKey;
		}
	}
	
}