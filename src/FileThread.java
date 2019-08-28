/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.util.List;
import java.util.ArrayList; 
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.*;
import javax.crypto.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.io.ByteArrayOutputStream;


public class FileThread extends Thread
{
	private final Socket socket;
	private FileServer fileServer;
	public FileThread(Socket _socket,FileServer _fileServer)
	{
		socket = _socket;
		fileServer=_fileServer;
	}
	public boolean checkToken(Token userToken)
	{
		try{
			byte a[] = userToken.toString().getBytes();				//get the to string of the token
			byte b[] = fileServer.keys.getPublic().getEncoded();	//get the byte array of the file servers public key
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			outputStream.write(a);
			outputStream.write(b);
			byte c[] = outputStream.toByteArray();				//put both a and b into one byte array
			Cipher cipher=Cipher.getInstance("RSA/None/NoPadding", "BC");
			cipher.init(Cipher.DECRYPT_MODE, fileServer.publicGroup);
			byte[] calculated=cipher.doFinal(userToken.getSignature()); //get signature from token
			MessageDigest hasher=MessageDigest.getInstance("SHA-256", "BC"); //maybe need specify more?
			hasher.update(c); //hash string-ed token along with the public key
			if(java.util.Arrays.equals(calculated, hasher.digest()))	//if the hash matches
			{
				if(java.util.Arrays.equals(userToken.getFileKey().getEncoded(), b))	//if the file server public key in the token matches the servers
					return true;
				else
					return false;
			}
			else
				return false;
		}catch(Exception e) {
			e.printStackTrace();
			return false;
		}
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
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			int sessionID = 0;
			do
			{
				Envelope e = (Envelope)input.readObject();
				if(symKeyEstablished) {
					System.out.println(e.getMessage());
					//get sealed obj
					e = DiffieHellman.decrypt(cipher, symKey, e);
					if(!DiffieHellman.verify(e, sessionID++, hmacKey)) {
						System.out.println("Verification failed. (filethread)");
					}
					else System.out.println("Verified. FT");
				}
				Envelope response = null;

				System.out.println("Request received: " + e.getMessage());

				//setup AES encryption with DH exchange
				if(e.getMessage().equals("INIT"))
				{
					response = new Envelope("FAIL");
					if(e.getObjContents().size() < 50) {
						PublicKey clientKey = (PublicKey)e.getObjContents().get(0);
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
				else if(e.getMessage().equals("AUTH"))
				{
					//set response to fail
					response = new Envelope("FAIL");
					//if the message has more than 1 object
					if(e.getObjContents().size() < 50)
					{
						//if the group server key is not null
						if(e.getObjContents().get(0) != null)
						{
							//get the gs pub key
							fileServer.publicGroup = (Key)e.getObjContents().get(0);
							response = new Envelope("OK");
							//add the file servers key to the response
							response.addObject(fileServer.keys.getPublic());
							//this would not normally need done as a user would just add the key to
							//the client app, but for simplicity we send it on initialization
						}
					}
					response = DiffieHellman.addData(response, sessionID++);
					response = DiffieHellman.addHMAC(response, hmacKey);
					response = DiffieHellman.encrypt(cipher, symKey, response);
					output.writeObject(response);
				}
				//used to authenticate the file server
				else if(e.getMessage().equals("CHECK_PUB"))
				{
					response = new Envelope("FAIL");
					if(e.getObjContents().size() < 50)
					{

						//if the challenge is not null
						if(e.getObjContents().get(0) != null)
						{
							byte [] challenge = (byte[])e.getObjContents().get(0);
							byte[] enrypChal = encrypt(challenge);
							response = new Envelope("FENCRYP");
							response.addObject(enrypChal);
						}
					}
					else System.out.println("size check failed");
					response = DiffieHellman.addData(response, sessionID++);
					response = DiffieHellman.addHMAC(response, hmacKey);
					response = DiffieHellman.encrypt(cipher, symKey, response);
					output.writeObject(response);
				}
				// Handler to list files that this user is allowed to see
				else if(e.getMessage().equals("LFILES"))
				{
					if(e.getObjContents().get(0)==null)
					{
						response=new Envelope("FAIL-BADTOKEN");
					}
					else
					{
						response=new Envelope("FAIL-BADTOKEN");
						Token theToken=(Token)e.getObjContents().get(0);
						if(checkToken(theToken))
						{
							ArrayList<String> groups=(ArrayList<String>)theToken.getGroups();
							response=new Envelope("OK");
							ArrayList<ShareFile> files=fileServer.fileList.getFiles();
							ArrayList<String> fileNames=new ArrayList();
							for(int x=0;x<files.size();x++)
							{
								if(groups.contains(files.get(x).getGroup()))
									fileNames.add(files.get(x).getPath());
							}
							response.addObject(fileNames);
							output.reset();//clears output stream
						}
						//encrypt
						response = DiffieHellman.addData(response, sessionID++);
						response = DiffieHellman.addHMAC(response, hmacKey);
						response = DiffieHellman.encrypt(cipher, symKey, response);
						output.writeObject(response);
					}
				}
				if(e.getMessage().equals("UPLOADF"))
				{

					if(e.getObjContents().size() < 80)
					{
						response = new Envelope("FAIL-BADCONTENTS");
					}
					else
					{
						if(e.getObjContents().get(0) == null) {
							response = new Envelope("FAIL-BADPATH");
						}
						if(e.getObjContents().get(1) == null) {
							response = new Envelope("FAIL-BADGROUP");
						}
						if(e.getObjContents().get(2) == null) {
							response = new Envelope("FAIL-BADTOKEN");
						}
						else {
							String remotePath = (String)e.getObjContents().get(0);
							String group = (String)e.getObjContents().get(1);
							Token yourToken = (Token)e.getObjContents().get(2); //Extract token
							int keyVersion=(Integer)e.getObjContents().get(3);
							byte[] encrVers=(byte[])e.getObjContents().get(4); 
							byte[] initVector=(byte[])e.getObjContents().get(5);
							ArrayList<String> test=(ArrayList<String>)yourToken.getGroups();
							if(!checkToken(yourToken))
								response=new Envelope("FAIL-TOKENMODIFIED");
							else if (fileServer.fileList.checkFile(remotePath)) {
								System.out.printf("Error: file already exists at %s\n", remotePath);
								response = new Envelope("FAIL-FILEEXISTS"); //Success
							}
							else if (!yourToken.getGroups().contains(group)) {
								System.out.printf("Error: user missing valid token for group %s\n", group);
								response = new Envelope("FAIL-UNAUTHORIZED"); //Success
							}
							else  {
								File file = new File("shared_files/"+remotePath.replace('/', '_'));
								file.createNewFile();
								FileOutputStream fos = new FileOutputStream(file);
								System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

								response = new Envelope("READY"); //Success
								response = DiffieHellman.addData(response, sessionID++);
								response = DiffieHellman.addHMAC(response, hmacKey);
								response = DiffieHellman.encrypt(cipher, symKey, response);
								output.writeObject(response);

								e = (Envelope)input.readObject();
								e = DiffieHellman.decrypt(cipher, symKey, e);
								if(!DiffieHellman.verify(e, sessionID++, hmacKey)) {
									System.out.println("Verification failed. (filethread)");
								}
								else System.out.println("Verified. FT");
								if(e.getMessage().equals("CHUNK"))
								{
									while (e.getMessage().compareTo("CHUNK")==0) {
										fos.write((byte[])e.getObjContents().get(0), 0, (Integer)e.getObjContents().get(1));
										response = new Envelope("READY"); //Success
										response = DiffieHellman.addData(response, sessionID++);
										response = DiffieHellman.addHMAC(response, hmacKey);
										response = DiffieHellman.encrypt(cipher, symKey, response);
										output.writeObject(response);
										e = (Envelope)input.readObject();
										e = DiffieHellman.decrypt(cipher, symKey, e);
										if(!DiffieHellman.verify(e, sessionID++, hmacKey)) {
											System.out.println("Verification failed. (filethread)");
										}
										else System.out.println("Verified. FT");
									}

									if(e.getMessage().compareTo("EOF")==0) {
										System.out.printf("Transfer successful file %s\n", remotePath);
										fileServer.fileList.addFile(yourToken.getSubject(), group, remotePath,keyVersion,encrVers,initVector);
										response = new Envelope("OK"); //Success
									}
									else {
										System.out.printf("Error reading file %s from client\n", remotePath);
										response = new Envelope("ERROR-TRANSFER"); //Success
									}
									fos.close();
								}
								else
								{
									response = new Envelope("FAIL");
								}
								
							}
						}
					}
					response = DiffieHellman.addData(response, sessionID++);
					response = DiffieHellman.addHMAC(response, hmacKey);
					response = DiffieHellman.encrypt(cipher, symKey, response);
					output.writeObject(response);
				}
				else if (e.getMessage().compareTo("DOWNLOADF")==0) {

					String remotePath = (String)e.getObjContents().get(0);
					Token t = (Token)e.getObjContents().get(1);
					ShareFile sf = fileServer.fileList.getFile("/"+remotePath);
					if(!checkToken(t))
						response=new Envelope("FAIL-TOKENMODIFIED");
					else if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_FILEMISSING");
						e = DiffieHellman.addData(e, sessionID++);
						e = DiffieHellman.addHMAC(e, hmacKey);
						e = DiffieHellman.encrypt(cipher, symKey, e);
						output.writeObject(e);

					}
					else if (!t.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
						e = DiffieHellman.addData(e, sessionID++);
						e = DiffieHellman.addHMAC(e, hmacKey);
						e = DiffieHellman.encrypt(cipher, symKey, e);
						output.writeObject(e);
					}
					else {

						try
						{
							File f = new File("shared_files/_"+remotePath.replace('/', '_'));
						if (!f.exists()) {
							System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
							e = new Envelope("ERROR_NOTONDISK");
							e = DiffieHellman.addData(e, sessionID++);
							e = DiffieHellman.addHMAC(e, hmacKey);
							e = DiffieHellman.encrypt(cipher, symKey, e);
							output.writeObject(e);

						}
						else {
							FileInputStream fis = new FileInputStream(f);

							do {
								byte[] buf = new byte[4096];
								if (e.getMessage().compareTo("DOWNLOADF")!=0) {
									System.out.printf("Server error: %s\n", e.getMessage());
									break;
								}
								e = new Envelope("CHUNK");
								int n = fis.read(buf); //can throw an IOException
								if (n > 0) {
									System.out.printf(".");
								} else if (n < 0) {
									System.out.println("Read error");

								}


								e.addObject(buf);
								e.addObject(new Integer(n));
								e = DiffieHellman.addData(e, sessionID++);
								e = DiffieHellman.addHMAC(e, hmacKey);
								e = DiffieHellman.encrypt(cipher, symKey, e);
								output.writeObject(e);

								e = (Envelope)input.readObject();
								e = DiffieHellman.decrypt(cipher, symKey, e);
								if(!DiffieHellman.verify(e, sessionID++, hmacKey)) {
									System.out.println("Verification failed. (filethread)");
								}
								else System.out.println("Verified. FT");


							}
							while (fis.available()>0);

							//If server indicates success, return the member list
							if(e.getMessage().compareTo("DOWNLOADF")==0)
							{

								e = new Envelope("EOF");
								e.addObject(sf.getKeyVersion());
								e.addObject(sf.getEncryptedKey());
								e.addObject(sf.getIV());
								e.addObject(sf.getGroup());
								e = DiffieHellman.addData(e, sessionID++);
								e = DiffieHellman.addHMAC(e, hmacKey);
								e = DiffieHellman.encrypt(cipher, symKey, e);
								output.writeObject(e);

								e = (Envelope)input.readObject();
								e = DiffieHellman.decrypt(cipher, symKey, e);
								if(!DiffieHellman.verify(e, sessionID++, hmacKey)) {
									System.out.println("Verification failed. (filethread)");
								}
								else System.out.println("Verified. FT");
								if(e.getMessage().compareTo("OK")==0) {
									System.out.printf("File data upload successful\n");
								}
								else {

									System.out.printf("Upload failed: %s\n", e.getMessage());

								}

							}
							else {

								System.out.printf("Upload failed: %s\n", e.getMessage());

							}
						}
						}
						catch(Exception e1)
						{
							System.err.println("Error: " + e.getMessage());
							e1.printStackTrace(System.err);

						}
					}
				}
				else if (e.getMessage().compareTo("DELETEF")==0) {

					String remotePath = (String)e.getObjContents().get(0);
					Token t = (Token)e.getObjContents().get(1);
					ShareFile sf = fileServer.fileList.getFile("/"+remotePath);
					if(!checkToken(t))
						response=new Envelope("FAIL-TOKENMODIFIED");
					else if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_DOESNTEXIST");
					}
					else if (!t.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
					}
					else {

						try
						{


							File f = new File("shared_files/"+"_"+remotePath.replace('/', '_'));

							if (!f.exists()) {
								System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR_FILEMISSING");
							}
							else if (f.delete()) {
								System.out.printf("File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
								fileServer.fileList.removeFile("/"+remotePath);
								e = new Envelope("OK");
							}
							else {
								System.out.printf("Error deleting file %s from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR_DELETE");
							}


						}
						catch(Exception e1)
						{
							System.err.println("Error: " + e1.getMessage());
							e1.printStackTrace(System.err);
							e = new Envelope(e1.getMessage());
						}
					}
					e = DiffieHellman.addData(e, sessionID++);
					e = DiffieHellman.addHMAC(e, hmacKey);
					e = DiffieHellman.encrypt(cipher, symKey, e);
					output.writeObject(e);

				}
				else if(e.getMessage().equals("DISCONNECT"))
				{
					socket.close();
					proceed = false;
					symKeyEstablished = false;
				}
			} while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
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
			cipher.init(Cipher.ENCRYPT_MODE, fileServer.keys.getPrivate());
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

	


}
