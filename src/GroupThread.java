/* This thread does all the work. It communicates with the client through Envelopes.
 *  
 */
import java.lang.Thread;
import java.net.Socket;
import java.io.*;
import java.util.*;
import java.security.*;
import java.math.BigInteger;
import javax.crypto.*;
import javax.crypto.SealedObject;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GroupThread extends Thread 
{
	
	private final Socket socket;
	private GroupServer my_gs;
	
	public GroupThread(Socket _socket, GroupServer _gs)
	{
		socket = _socket;
		my_gs = _gs;
	}
	
	public void run()
	{
		boolean proceed = true;
		boolean symKeyEstablished = false;
		SecretKey[] key_set = null;
		SecretKey symKey = null;
		SecretKey hmacKey = null;
		Cipher cipher = null;
		

		try
		{
			//Announces connection and opens object streams
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			int sessionID = 0;
			do
			{
				//if encryption is established we must decrypt
				Envelope message = (Envelope)input.readObject();
				
				if(symKeyEstablished) {
					System.out.println(message.getMessage());
					//get sealed obj
					message = DiffieHellman.decrypt(cipher, symKey, message);
					if(!DiffieHellman.verify(message, sessionID++, hmacKey)) {
						System.out.println("Verification failed. GT");
					}
					else System.out.println("Verified. GT");
				}

				System.out.println("Request received: " + message.getMessage());
				Envelope response = null;
				
				if(message.getMessage().equals("INIT")) //used to initialize the system
				{
					response = new Envelope("FAIL");
					if(message.getObjContents().size() < 50) {
						PublicKey clientKey = (PublicKey)message.getObjContents().get(0);
						//new keypair
						KeyPair serverKeyPair = DiffieHellman.newKeyPair();
						//new agreement
						KeyAgreement serverAgreement = DiffieHellman.newKeyAgreement(serverKeyPair.getPrivate());
						//new secret
						key_set = DiffieHellman.newSecretKeySet(serverAgreement, clientKey);
						symKey = key_set[0];
						hmacKey = key_set[1];
						//new cipher
						cipher = DiffieHellman.newCipher();
						symKeyEstablished = true;
						response = new Envelope("DONE");
						//send back public key
						response.addObject(serverKeyPair.getPublic());
					}
					output.writeObject(response);
				}
				else if(message.getMessage().equals("AUTH")) 
				{
					//set response to fail
					response = new Envelope("FAIL");
					//if the message has more than 2 objects
					
					//if the admins key is not null
					if(message.getObjContents().get(0) != null)
					{
						//if the admins name is not null
						if(message.getObjContents().get(1) != null)
						{
							//get the admins key
							Key adminKey = (Key)message.getObjContents().get(0);
							//get the username
							String userName = (String)message.getObjContents().get(1);
							
							//if successfully initialized
							if(initialize(adminKey, userName))
							{
								response = new Envelope("DONE"); //Success
								//add the servers public key to the envelope
								response.addObject(my_gs.keys.getPublic());
							}
						}
					}
					
					response = DiffieHellman.addData(response, sessionID++);
					response = DiffieHellman.addHMAC(response, hmacKey);
					response = DiffieHellman.encrypt(cipher, symKey, response);
					output.writeObject(response);//ouput either done or fail
				}
				else if(message.getMessage().equals("GET"))	//see if user exists
				{
					response = new Envelope("FAIL");		//set the response to fail
					
							
							String username = (String)message.getObjContents().get(0); //Get the username
							Key fileKey = (Key)message.getObjContents().get(1);		//get the file servers key
							
							//make sure username is not null
							if(username == null)
							{
							}
							else	//user name is not null
							{
								//make sure the user exists
								if(my_gs.userList.checkUser(username))
								{
									//generate a random challenge
									SecureRandom rand = new SecureRandom();
									//used to hold the random number as a byte array
									byte [] num = null;
									//used to hold the random number as a integer
									int n = 0;
									//generate the random number
									n = rand.nextInt(2147483647);
									//convert the random num into a byte array
									num = BigInteger.valueOf(n).toByteArray();
									//responsd that the user exists, send the challenge
									response = new Envelope("OK");
									response.addObject(num);	//the challenge
									response = DiffieHellman.addData(response, sessionID++);
									response = DiffieHellman.addHMAC(response, hmacKey);
									response = DiffieHellman.encrypt(cipher, symKey, response);
									output.writeObject(response);	//send the message
							
									//get the response of the challenge
									message = (Envelope)input.readObject();
									message=DiffieHellman.decrypt(cipher,symKey,message);
									if(!DiffieHellman.verify(message, sessionID++, hmacKey)) {
										System.out.println("Verification failed. GT");
									}
									else System.out.println("Verified. GT");
									//System.out.println(message.getMessage());
									//set response to fail
									response = new Envelope("FAIL");
									//clear the output stream
									output.reset();
									//if the user still wants the token
									if(message.getMessage().equals("RECEIVE"))
									{
										
													//holds the randomnumber encrypted with private key
													byte[] cipherText = (byte [])message.getObjContents().get(0);
													//holds the challenge for the server to encrypt
													byte[] c2 = (byte[])message.getObjContents().get(1);
													//if the user was verified by decrypting the challenge
													if(decrypt(cipherText, num, username))
													{
														//used to hold the encrypted challenge the server will send back
														byte[] encryption = encrypt(c2);
														//generate the token
														UserToken yourToken = createToken(username, fileKey);
														ArrayList<String> groups=my_gs.userList.getUserGroups(username);
														HashMap<String,ArrayList<SecretKey>> groupKeys=new HashMap<String,ArrayList<SecretKey>>();
														for(String group:groups)
														{
															groupKeys.put(group,my_gs.groupList.getKeys(group));
														}
														//yourToken=signToken(yourToken);
														//set response to done
														response = new Envelope("DONE");
														response.addObject(yourToken);//add the token to the envelope
														response.addObject(encryption);//add the challenge to the envelope
														response.addObject(groupKeys);
														//output.writeObject(response);
													
													}
												
									}		
											
										
									
								}
							}
						
					
					response = DiffieHellman.addData(response, sessionID++);
					response = DiffieHellman.addHMAC(response, hmacKey);
					response = DiffieHellman.encrypt(cipher, symKey, response);
					output.writeObject(response);//output either the done envelope of fail envelope	
				}
				else if(message.getMessage().equals("CUSER")) //Client wants to create a user
				{
					//if the message has 3 objects
					response = new Envelope("FAIL");
						
									String username = (String)message.getObjContents().get(0); //Extract the username
									Token yourToken = (Token)message.getObjContents().get(1); //Extract the token
									Key publicKey = (Key)message.getObjContents().get(2);//get the new users public key
									if(checkToken(yourToken))
									{
										//if user added to the system
										if(createUser(username, yourToken, publicKey))
										{
											response = new Envelope("OK"); //Success
										}
									}
								
							
						
					
					response = DiffieHellman.addData(response, sessionID++);
					response = DiffieHellman.addHMAC(response, hmacKey);
					response = DiffieHellman.encrypt(cipher, symKey, response);
					output.writeObject(response);//output either ok or fail
				}
				else if(message.getMessage().equals("DUSER")) //Client wants to delete a user
				{
					
					
						response = new Envelope("FAIL");
						
						
								String username = (String)message.getObjContents().get(0); //Extract the username
								//UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								Token yourToken = (Token)message.getObjContents().get(1); //Extract the token
								if(checkToken(yourToken))
								{
									if(deleteUser(username, yourToken))
									{
										response = new Envelope("OK"); //Success
									}
								}
							
						
					
					response = DiffieHellman.addData(response, sessionID++);
					response = DiffieHellman.addHMAC(response, hmacKey);
					response = DiffieHellman.encrypt(cipher, symKey, response);
					output.writeObject(response);
				}
				else if(message.getMessage().equals("CGROUP")) //Client wants to create a group
				{
				    
						response = new Envelope("FAIL");
						
								String groupName = (String)message.getObjContents().get(0); //Extract the groupname
								Token yourToken = (Token)message.getObjContents().get(1); //Extract the token
								if(checkToken(yourToken))
								{
									if(createGroup(groupName, yourToken))
									{
										//response.addObject(yourToken);
										response = new Envelope("OK"); //Success
									}
								}
							
						
					
					response = DiffieHellman.addData(response, sessionID++);
					response = DiffieHellman.addHMAC(response, hmacKey);
					response = DiffieHellman.encrypt(cipher, symKey, response);
					output.writeObject(response);
				}
				else if(message.getMessage().equals("DGROUP")) //Client wants to delete a group
				{
				    
						response = new Envelope("FAIL");
					
						
								String groupName = (String)message.getObjContents().get(0); //Extract the groupname
								Token yourToken = (Token)message.getObjContents().get(1); //Extract the token
								if(checkToken(yourToken))
								{
									if(deleteGroup(groupName, yourToken))
									{
										response = new Envelope("OK"); //Success
									}
								}
							
						
						
					
					response = DiffieHellman.addData(response, sessionID++);
					response = DiffieHellman.addHMAC(response, hmacKey);
					response = DiffieHellman.encrypt(cipher, symKey, response);
					output.writeObject(response);
				}
				else if(message.getMessage().equals("LMEMBERS")) //Client wants a list of members in a group
				{
					//temp list of group members
					ArrayList<String> temp;
				    
						response = new Envelope("FAIL");						
						
								String groupName = (String)message.getObjContents().get(0); //Extract the groupname
								Token yourToken = (Token)message.getObjContents().get(1); //Extract the token
								if(checkToken(yourToken))
								{
									temp = getMembers(groupName, yourToken);
								}
								yourToken = (Token)message.getObjContents().get(1); //Extract the token
								temp=null;
								if(!checkToken(yourToken))
									response=new Envelope("FAIL-TOKENMODIFIED");
								else
									temp = getMembers(groupName, yourToken);
								//Respond to the client. On error, the client will receive a null list
								if(temp == null)
								{
									response = new Envelope("FAIL");
									response.addObject(null);
									output.reset();
									response = DiffieHellman.addData(response, sessionID++);
									response = DiffieHellman.addHMAC(response, hmacKey);
									response = DiffieHellman.encrypt(cipher, symKey, response);
									output.writeObject(response);
								}
								else
								{
									response = new Envelope("OK");
									response.addObject(temp);
									output.reset();//used to clear the output stream
									response = DiffieHellman.addData(response, sessionID++);
									response = DiffieHellman.addHMAC(response, hmacKey);
									response = DiffieHellman.encrypt(cipher, symKey, response);
									output.writeObject(response);
								}
							
						
					}
					
				
				else if(message.getMessage().equals("AUSERTOGROUP")) //Client wants to add user to a group
				{
				    
						response = new Envelope("FAIL");
						
										String userName = (String)message.getObjContents().get(0);
										String groupName = (String)message.getObjContents().get(1);
										Token yourToken = (Token)message.getObjContents().get(2);
										if(checkToken(yourToken))
										{
											if(addToGroup(userName, groupName, yourToken))
											{
												response = new Envelope("OK");
											}
										}
								
							
						
					
					response = DiffieHellman.addData(response, sessionID++);
					response = DiffieHellman.addHMAC(response, hmacKey);
					response = DiffieHellman.encrypt(cipher, symKey, response);		
					output.writeObject(response);
				}
				else if(message.getMessage().equals("RUSERFROMGROUP")) //Client wants to remove user from a group
				{
				    
						response = new Envelope("FAIL");
						
						
										String userName = (String)message.getObjContents().get(0);
										String groupName = (String)message.getObjContents().get(1);
										Token yourToken = (Token)message.getObjContents().get(2);
										if(checkToken(yourToken))
										{
											if(removeFromGroup(userName, groupName, yourToken))
											{
												response = new Envelope("OK");
											}
										}
								
							
						
					
					response = DiffieHellman.addData(response, sessionID++);
					response = DiffieHellman.addHMAC(response, hmacKey);
					response = DiffieHellman.encrypt(cipher, symKey, response);
					output.writeObject(response);
				}
				else if(message.getMessage().equals("DISCONNECT")) //Client wants to disconnect
				{
					socket.close(); //Close the socket
					proceed = false; //End this communication loop
					symKeyEstablished = false;
				}
				else
				{
					response = new Envelope("FAIL"); //Server does not understand client request
					output.writeObject(response);
				}
				my_gs.save();
			}while(proceed);	
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
	
	private boolean decrypt(byte [] cipherText, byte[] num, String username)
	{
		//add bouncycastle as a security provider
		Security.addProvider(new BouncyCastleProvider());
		//create the cipher variable
		Cipher cipher = null;
		//try to initialize the cipher
		try{
			cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
		}
		catch(NoSuchAlgorithmException e)
		{
			System.out.println("Algoirthm does not exist for cipher RSA/None/NoPadding");
		}
		catch(NoSuchProviderException e)
		{
			System.out.println("No such provider for cipher decryption");
		}
		catch(NoSuchPaddingException e)
		{
			System.out.println("Padding exception RSA");
		}
		
		//set the cipher to decrypt mode with the users public key
		try{
			//get the users public key
			Key userKey = my_gs.userList.getKey(username);
			//will print out the users public key
			//System.out.println("\n\nRSA Public key: " + Utils.toHex(userKey.getEncoded()));
			
			//initialize the cipher
			cipher.init(Cipher.DECRYPT_MODE, userKey);
		}
		catch(InvalidKeyException e)
		{
			System.out.println("InvalidKeyException RSA decryption");
		}
		
		//variable to hold result of decryption
		byte [] plainText = null;
		//decrypt the message
		try{
			//get the decrypted message
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
		//convert the decrypted value to a int
		int resp = new BigInteger(plainText).intValue();
		//conver the challenge back to a int
		int key = new BigInteger(num).intValue();
		
		//see if the values match, authenticating the user
		if(resp == key)
		{
			return true;	//true if they match
		}
		else
		{
			return false;
		}
	}
	
	private byte[] encrypt(byte [] c2)
	{
		//add bouncycastle security provider
		Security.addProvider(new BouncyCastleProvider());
		//create a variable cipher
		Cipher cipher = null;
		//try to initialize the cipher
		try{
			cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
		}
		catch(NoSuchAlgorithmException e)
		{
			System.out.println("Algoirthm does not exist for RSA encryption");
		}
		catch(NoSuchProviderException e)
		{
			System.out.println("No provider for RSA encryption");
		}
		catch(NoSuchPaddingException e)
		{
			System.out.println("Padding exception RSA");
		}
		
		//start encryption using servers private key
		try{
			cipher.init(Cipher.ENCRYPT_MODE, my_gs.keys.getPrivate());
		}
		catch(InvalidKeyException e)
		{
			System.out.println("Invalid private key RSA encryption");
		}
		
		//create a variable for the cipher text
		byte [] cipherText = null;
		//System.out.println("Byte input to RSA: " + Utils.toHex(c2));
		
		//encrypt the challenge
		try{	
			cipherText = cipher.doFinal(c2);
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
	//Jonathan Zhang
	//MIGHT NEED TO MOVE THIS CODE TO SOMEWHERE ELSE (again)
		
	//create hash of string'd token, sign with private, store in token
	public void signToken(Token token, Key fileKey)
	{
		try{
			
			byte a[] = token.toString().getBytes();				//get the tostring of the token as a byte array
			byte b[] = fileKey.getEncoded();					//get the file keys byte array
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			outputStream.write(a);
			outputStream.write(b);
			byte c[] = outputStream.toByteArray();			//combine the tokens string and the file keys byte array
			MessageDigest hasher=MessageDigest.getInstance("SHA-256", "BC"); //maybe need specify more?
			hasher.update(c); //hash string-ed token and the file key
			token.setSignature(encrypt(hasher.digest())); //sign with private
		}catch(Exception e){
			e.printStackTrace();
		}
	}
	//check if the signature in token matches with rest of token's contents
	public boolean checkToken(Token token)
	{
		try{
			byte a[] = token.toString().getBytes();		//get the toString of the token in a byte array
			byte b[] = token.getFileKey().getEncoded();	//get the file servers key from the token as a byte array
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			outputStream.write(a);
			outputStream.write(b);
			byte c[] = outputStream.toByteArray();		//place a and b into one byte array
			Cipher cipher=Cipher.getInstance("RSA/None/NoPadding", "BC");
			cipher.init(Cipher.DECRYPT_MODE, my_gs.keys.getPublic());
			byte[] calculated=cipher.doFinal(token.getSignature()); //get signature from token
			MessageDigest hasher=MessageDigest.getInstance("SHA-256", "BC"); //maybe need specify more?
			hasher.update(c); //hash string-ed token along with the byte array of the file servers key
			if(java.util.Arrays.equals(calculated, hasher.digest()))
				return true;
			else
				return false;
		}catch(Exception e) {
			e.printStackTrace();
			return false;
		}
	}
	//Method to create tokens
	private Token createToken(String username, Key fileKey) 
	{
		//Check that user exists
		if(my_gs.userList.checkUser(username))
		{
			//Issue a new token with server's name, user's name, and user's groups
			Token yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username), fileKey);
			//sets the User't token in the UserList
			//my_gs.userList.setToken(username, yourToken);
			signToken(yourToken, fileKey);		//pass the token and the file servers key to sign
			return yourToken;
		}
		else
		{
			return null;
		}
	}
	
	
	//Method to create a user
	private boolean createUser(String username, UserToken yourToken, Key publicKey)
	{
		String requester = yourToken.getSubject();
		
		//Check if requester exists
		if(my_gs.userList.checkUser(requester))
		{
			//Get the user's groups
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administrator
			if(temp.contains("ADMIN"))
			{
				//Does user already exist?
				if(my_gs.userList.checkUser(username))
				{
					return false; //User already exists
				}
				else
				{
					my_gs.userList.addUser(username, publicKey);
					return true;
				}
			}
			else
			{
				return false; //requester not an administrator
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}
	
	//Method to delete user from group
	private boolean removeFromGroup(String userName, String groupName, UserToken token)
	{
		
		String requester = token.getSubject();
		
		//check if requester exists
		if(my_gs.userList.checkUser(requester))
		{
			//check if the group exists
			if(my_gs.groupList.checkGroup(groupName))
			{
				//check if they are the owner of the group
				ArrayList<String> temp = my_gs.userList.getUserOwnership(requester);
				ArrayList<String> owners = my_gs.groupList.getGroupOwnership(groupName);
				//if the user is the owner of the group
				if(temp.contains(groupName))
				{
					//Do not allow admin group to be deleted
					if(groupName.equalsIgnoreCase("ADMIN"))
					{
						return false;
					}
					//check if the user to remove exists
					if(my_gs.userList.checkUser(userName))	
					{
						//see if requester if removing himself
						if(userName.equalsIgnoreCase(requester))
						{
							//see if they only owner
							if(owners.size() == 1)
							{
								//Does not allow admin group to be deleted
								if(!groupName.equalsIgnoreCase("ADMIN"))
								{
									//if the only owner, delete the group
									deleteGroup(groupName, token);
									return true;
								}
							}
							else //not the only owner, so just delete user from group
							{
								my_gs.userList.removeGroup(userName, groupName);
								my_gs.userList.removeOwnership(userName, groupName);
								my_gs.groupList.removeMember(groupName, userName);
								my_gs.groupList.removeOwnership(groupName, userName);
								return true;
							
							}
						}//end of if
						//remove the group to the userlists user
						my_gs.userList.removeGroup(userName, groupName);
						//remove the user from the grouplist
						my_gs.groupList.removeMember(userName, groupName);
						
						return true;
					}
				}
			}
			
		}
			
		return false;	
		
	}
	//Method to delete a user
	private boolean deleteUser(String username, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		
		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administer
			if(temp.contains("ADMIN"))
			{
				//added in: Does not allow deletion of ADMIN
				ArrayList <String> admin = my_gs.groupList.getGroupMembers("ADMIN");
				//do not allow admin to delete themself
				if(username.equalsIgnoreCase(requester))
				{
					if(admin.size() == 1)
					{
						return false;
					}
				}
				//Does user exist?
				if(my_gs.userList.checkUser(username))
				{
					//User needs deleted from the groups they belong
					ArrayList<String> deleteFromGroups = new ArrayList<String>();
					
					//This will produce a hard copy of the list of groups this user belongs
					for(int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++)
					{
						deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));
					}
					
					//Delete the user from the groups
					//If user is the owner, removeMember will automatically delete group!
					for(int index = 0; index < deleteFromGroups.size(); index++)
					{
						my_gs.groupList.removeMember(username, deleteFromGroups.get(index)); 
					}
					
					//If groups are owned, they must be deleted
					ArrayList<String> deleteOwnedGroup = new ArrayList<String>();
					
					//Make a hard copy of the user's ownership list
					for(int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++)
					{
						deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
					}
					
					//Delete owned groups
					for(int index = 0; index < deleteOwnedGroup.size(); index++)
					{
						//Use the delete group method. Token must be created for this action
						deleteGroup(deleteOwnedGroup.get(index), new Token(my_gs.name, username, deleteOwnedGroup, null));
					}
					
					//Delete the user from the user list
					my_gs.userList.deleteUser(username);
					
					return true;	
				}
				else
				{
					return false; //User does not exist
					
				}
			}
			else
			{
				return false; //requester is not an administer
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}
	
	//Method to create a group
	private boolean createGroup(String groupName, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		
		//check if requester exists
		if(my_gs.userList.checkUser(requester))
		{
			
			//check if the group already exists
			if(!my_gs.groupList.checkGroup(groupName))
			{
					//add the user as the owner of the group
					my_gs.userList.addOwnership(requester, groupName);
					//add the group to the users groups
					my_gs.userList.addGroup(requester, groupName);
					//add the group to the list of groups
					my_gs.groupList.addGroup(groupName, yourToken.getSubject());
					//add the group the the users token
					//yourToken.addGroup(groupName);
					
					return true;
			}
			else
			{
				//group must already exist
				return false;
			}
		}
		else
		{
			return false; //requester does not exists
		}
	}
	
	//method to add member to a group
	private boolean addToGroup(String userName, String groupName, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		
		//check if requester exists
		if(my_gs.userList.checkUser(requester))
		{
			
			//check if they are the owner of the group
			ArrayList<String> temp = my_gs.userList.getUserOwnership(requester);
			
			//if the user is the owner of the group
			if(temp.contains(groupName))
			{
				//check if the user to add exists
				if(my_gs.userList.checkUser(userName))	
				{
					ArrayList<String> userGroups = my_gs.userList.getUserGroups(userName);
					//if already in group, do not add
					if(userGroups.contains(groupName))
					{
						return false;
					}
					//add the group to the userlists user
					my_gs.userList.addGroup(userName, groupName);
					//add the user to the grouplist
					my_gs.groupList.addUser(groupName, userName);	
					return true;
				}	
			}
			
		}
		return false;				
	}//end of addToGroup method
	
	//Method to delete a group
	//Note: does not allow admin group to be deleted
	private boolean deleteGroup(String groupName, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		
		//Does not allow you to delete the admin group
		if(!groupName.equalsIgnoreCase("ADMIN"))
		{
		
			//Does requester exist?
			if(my_gs.userList.checkUser(requester))
			{
				//Does the group exist
				if(my_gs.groupList.checkGroup(groupName))
				{
					//The list of groups that the user has ownership in
					ArrayList<String> temp = my_gs.userList.getUserOwnership(requester);
			
					//the user can delete the group if true
					if(temp.contains(groupName))
					{
						//delete the group from the group list
						ArrayList<String> delGroup = my_gs.groupList.removeGroup(groupName);
						//This will remove the group from each users group list
						int i = 0;
						while(i < delGroup.size())
						{
							String user = delGroup.get(i);
							my_gs.userList.removeGroup(user, groupName);
							i++;
						}
						return true;
					}
					else
					{
						//the user cannot delete the group as they are not the owner
						return false;
					}
				}
			} 
		}
		//did not pass one of if statements if here
		return false;
	}
	
	//method to get members of a group
	private ArrayList<String> getMembers(String groupName, UserToken yourToken)
	{
		ArrayList<String> memList = null;
		String requester = yourToken.getSubject();
		
		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			//The list of groups that the user has ownership in
			ArrayList<String> temp = my_gs.userList.getUserOwnership(requester);
			
			//if the user is the owner of the group
			if(temp.contains(groupName))
			{
				//if the GroupList contains the group
				if(my_gs.groupList.checkGroup(groupName))
				{
					memList = my_gs.groupList.getGroupMembers(groupName);
				}
			}
		}
		
		return memList;	
		
	}//end of getMembers method
	
	//method to set the admins public key on first used
	private boolean initialize(Key adminKey, String userName)
	{	
		//Check if requester exists
		if(my_gs.userList.checkUser(userName))
		{
			//Get the user's groups
			ArrayList<String> temp = my_gs.userList.getUserGroups(userName);
			//requester needs to be an administrator
			if(temp.contains("ADMIN"))
			{
					my_gs.userList.setUserKey(userName, adminKey);
					System.out.println("KEY ADDED TO SERVER");
					return true;
			}
			else
			{
				System.out.println("KEYNOTADDED");
				return false; //requester not an administrator
			}
		}
		else
		{
			System.out.println("KEYNOTADDED");
			return false; //requester does not exist
		}

	}

		
			
			
			
	
}
