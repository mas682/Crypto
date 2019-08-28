

import java.util.NoSuchElementException;
import java.util.Scanner;
import java.io.IOException;
import java.math.BigInteger;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.ByteBuffer;
 import javax.crypto.spec.IvParameterSpec;
import java.util.ListIterator;
import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.*;
import javax.crypto.*;

//Matt Stropkey 
//CS1653 project phase2

//may need toimplement list iterator

/**
 * MyClientApp is a application for simulating a group file server.
 * It is a client of the GroupClient and File classes.
 */
public class MyClientApp {

    // a scanner to get input from the user 
    private static Scanner input = new Scanner(System.in);
	private static GroupClient groupServ;
	private static FileClient fileServ;
	private static KeySaver keys;
	private static Key groupServerPublicKey;
	private static Key fileServerPublicKey;
	private static boolean fServer;
	private static HashMap<String,ArrayList<SecretKey>> groupKeys;
	private static byte[] ivForFileOps; //
    public static void main(String args[]) {
		//will need to shares admins public key with server before attempting to login

		keys = new KeySaver();
		keys.start();
		keys.save();
		if(args.length > 0)
		{
			groupServ = new GroupClient(args[0], Integer.parseInt(args[1]));
			fileServ = new FileClient(args[2], Integer.parseInt(args[3]));
			boolean gConnect = false;
			gConnect = groupServ.isConnected();
			if(!gConnect)
			{
				System.out.println("Connection to Group Server failed!");
			}
		}
		else
		{
			groupServ = new GroupClient("localhost", GroupServer.SERVER_PORT);	
			fileServ=new FileClient("localhost",FileServer.SERVER_PORT);
			boolean gConnect = false;
			gConnect = groupServ.isConnected();
			if(!gConnect)
			{
				System.out.println("Connection to Group Server failed!");
			}
		}

		if(!groupServ.initialize()) {
			System.out.println("Failed to initialize AES encryption with group server.");
			System.exit(-1);
		}
		else {
			System.out.println("Group server initialized AES.");
		}

		if(!fileServ.initialize()) {
			System.out.println("Failed to initialize AES encryption with file server.");
			System.exit(-1);
		}
		else System.out.println("File server initialized AES.");

		if(keys.init())
		{
			System.out.print("Enter your username for the group server to initialize the app: ");
			String initName = input.next();
			input.nextLine();
			groupServerPublicKey = groupServ.authenticate(keys.userKeys.getPublicKey(initName), initName);
			if(groupServerPublicKey == null)
			{
				System.out.println("Server key not obtained thus the system has not been initialized");
				System.exit(-1);
			}
			else
			{
				keys.userKeys.changeServerKey(initName, groupServerPublicKey);
				keys.save();
			}
			if(groupServerPublicKey != null) {
				fileServerPublicKey = fileServ.authenticate(groupServerPublicKey);
				if(fileServerPublicKey != null) {
					System.out.println("Received public key of file server.");
					keys.userKeys.changeFileKey(initName, fileServerPublicKey);
					keys.save();
				}
				else
				{
					System.out.println("Failed to receive file server public key.");
					System.exit(-1);
				}
			}
		}
		else
		{
			System.out.print("Enter your username to start the application: ");
			String initName = input.next();
			input.nextLine();
			if(keys.userKeys.checkUser(initName))
			{
				fileServerPublicKey = fileServ.authenticate(keys.userKeys.getServerKey(initName));
				if(fileServerPublicKey != null) {
					System.out.println("Received public key of file server.");
					keys.userKeys.changeFileKey(initName, fileServerPublicKey);
					keys.save();
				}
				else
				{
					System.out.println("Failed to receive file server public key.");
					System.exit(-1);
				}
			}
			else
			{
				System.out.println("Unable to start the application as the username does not exist");
				System.exit(-1);
			}
		}
		if(fileServerPublicKey != null)
		{
			fServer = fileServ.checkPublicKey(fileServerPublicKey);
		}
		else
		{
			fServer = false;
			System.out.println("Unable to authenticate file server as no key provided");
			System.exit(-1);
		}
		
		

		int selection = -1;
        while (selection != 0) {
            System.out.println();
            System.out.println("Group Server Main Menu");
            System.out.println("1. Login");    
            System.out.println("0. Quit");
            System.out.print("Selection: ");

            try {
                selection = input.nextInt();
            } catch (NoSuchElementException e) {
                selection = -1;
            } catch (IllegalStateException e) {
                selection = -1;
            }
            input.nextLine();

            switch (selection) {
                case 1:
                    login();
                    break;
                case 0:
                    quit();
                    break;
                default:
                    // Invalid, just ignore and let loop again
                    break;
            }
        }
    }

	
	public static void userOptions(String userName)
	{
		 int selection = -1;

        while (selection != 0) {
			if(!groupServ.isConnected())
			{
				groupServ.connect("localhost", GroupServer.SERVER_PORT);
			}
            System.out.println();
            System.out.println(userName + "'s options: ");
            System.out.println("1. Create a new user");
			System.out.println("2. Delete a user");
			System.out.println("3. Create a group");
			System.out.println("4. Add user to a group");
			System.out.println("5. Remove a user from a group");
			System.out.println("6. Delete a group");
			System.out.println("7. List members of a group");
			System.out.println("8. Upload a file to a group");
			System.out.println("9. Download a file");
			System.out.println("10. Delete a file");
			System.out.println("11. Display my files");
            System.out.println("0. Quit");
            System.out.print("Selection: ");

            try {
                selection = input.nextInt();
            } catch (NoSuchElementException e) {
                selection = -1;
            } catch (IllegalStateException e) {
                selection = -1;
            }
            input.nextLine();

            switch (selection) {
                case 1:
                    createNewUser(userName);
                    break;	
				case 2:
					deleteUser(userName);
					break;
				case 3:
					create(userName);
					break;
				case 4:
					addToGroup(userName);
					break;
				case 5:
					removeFromGroup(userName);
					break;
				case 6:
					deleteGroup(userName);
					break;
				case 7:
					listMembers(userName);
					break;
				case 8:
					try{uploadFile(userName);}
					catch(Exception e)
					{
						System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
					}
					break;
				case 9:
					try{downloadFile(userName);}
					catch(Exception e)
					{
						System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
					}
					break;
				case 10: 
					deleteFile(userName);
					break;
				case 11: 
					displayFiles(userName);
					break;
                case 0:
                    return;
                default:
                    // Invalid, just ignore and let loop again
                    break;
            }//end of switch
			keys.save();
        }//end of while loop
		
	}//end of userOptions method

    /**
     * Allows the user to login to the server
     */
    public static void login() {
		System.out.print("Username: ");								//get the users username
		String userName = input.nextLine();							//read in users username
		Key publicKey = keys.userKeys.getPublicKey(userName);		//TEST IF YOU PUT IN A FALSE NAME
		if(publicKey == null)
		{
			System.out.println("User does not exist");
			return;
		}
		if(fServer)
		{
			byte [] user = keys.userKeys.getFileServerKey(userName).getEncoded();
			byte [] fTemp = fileServerPublicKey.getEncoded();
				if(java.util.Arrays.equals(user, fTemp))
				{
					System.out.println("The file server has been authenticated and it's public key matches the one you provided");
				}
				else
				{
					System.out.println("WARNING!!!!!");
					System.out.println("THE KEY THAT YOU HAVE PROVIDED DOES NOT MATCH THE FILE SERVERS PUBLIC KEY");
					System.out.println("PROCEED AT YOUR OWN RISK");
				}
				int selection = -1;
				while(selection != 1)
				{
					System.out.print("Enter a 1 to continue or 0 to exit: ");
					try {
						selection = input.nextInt();
					} catch (NoSuchElementException e) {
					selection = -1;
					} catch (IllegalStateException e) {
						selection = -1;
					}
					input.nextLine();
					if(selection == 0)
					{
						return;
					}
				}
		}
		else
		{
			System.out.println("WARNING!!!");
			System.out.println("The file server has not been authenticated");
			//System.exit(-1);
		}
		ArrayList<Object> tempList= groupServ.getToken(userName, keys.userKeys.getPublicKey(userName),
								keys.userKeys.getPrivateKey(userName), keys.userKeys.getServerKey(userName), fileServerPublicKey);	
		UserToken userToke=(UserToken)tempList.get(0);//get the token of the user
		groupKeys=(HashMap<String,ArrayList<SecretKey>>)tempList.get(1);
		if(userToke == null)											//if the token does not exist
		{
			System.out.println("User does not exist\n");	
			return;													//return to main menu if token does not exist
		}
		else{
			userOptions(userName);  						//jump to user menu, depending on if they are a admin or just user
        }
    }
	 
	/**
	 * Allows the user to create a new group.
	 */
	public static void create(String userName)
	{
		System.out.print("Enter the new groups name: ");
		String gName = input.nextLine();
		boolean created = groupServ.createGroup(gName, (UserToken)groupServ.getToken(userName, keys.userKeys.getPublicKey(userName), 
									keys.userKeys.getPrivateKey(userName), keys.userKeys.getServerKey(userName),fileServerPublicKey).get(0));
		if(!created)
		{
			System.out.println("The group name " + gName + " already exists");
		}
		else
		{
			System.out.println("The new group " + gName + " has been created.");
		}
	}
	
	/**
	 * Allows the user to delete a user
	 */
	 public static void deleteUser(String userName)
	 {
		 System.out.print("Enter the name of the user to delete: ");
		 String uName = input.nextLine();
		 boolean deleted = groupServ.deleteUser(uName, (UserToken)groupServ.getToken(userName, keys.userKeys.getPublicKey(userName),
							keys.userKeys.getPrivateKey(userName), keys.userKeys.getServerKey(userName), fileServerPublicKey).get(0));
		 if(!deleted)
		 {
			 System.out.println("Unable to delete the user going by the username of " + uName);
		 }
		 else
		 {
			 System.out.println("The user " + uName + " has been deleted.");
			 if(!keys.userKeys.removeUser(uName))
			 {
				 System.out.println("ERROR REMOVING USER KEYS");
			 }
		 
		 }
	 }
	
	/**
	 * Allows a user to add another user to a group.
	 */
	public static void addToGroup(String userName)
	{
		System.out.print("Enter the name of the group that you would like to add the user to: ");
		String gName = input.nextLine();
		System.out.print("Enter the name of the user to add to the group: ");
		String uName = input.nextLine();
		ArrayList<Object> temp=groupServ.getToken(userName, keys.userKeys.getPublicKey(userName),
							keys.userKeys.getPrivateKey(userName), keys.userKeys.getServerKey(userName), fileServerPublicKey);
		boolean added = groupServ.addUserToGroup(uName, gName,(UserToken)temp.get(0));
		if(!added)
		{
			System.out.println("The user " + uName + " was unable to be added to the group " + gName + ".");
			
		}
		else
		{
			System.out.println("The user " + uName + " was added to the group " + gName + ".");
		}
	}//end of addToGroup method
	
	/**
	 * Allows a user to remove another user from a group.
	 */
	public static void removeFromGroup(String userName)
	{
		System.out.print("Enter the name of the group that you would like to remove a user from: ");
		String gName = input.nextLine();
		System.out.print("Enter the name of the user to remove from the group: ");
		String uName = input.nextLine();
		boolean removed = groupServ.deleteUserFromGroup(uName, gName,(UserToken) groupServ.getToken(userName, keys.userKeys.getPublicKey(userName), keys.userKeys.getPrivateKey(userName),
								keys.userKeys.getServerKey(userName), fileServerPublicKey).get(0));
		if(!removed)
		{
			System.out.println("The user " + uName + " was unable to be removed from the group " + gName + ".");
		}
		else
		{
			System.out.println("The user " + uName + " was removed from the group " +gName + ".");
		}
	}//end of removeFromGroup method
	
	/**
	 * Allows a user to delete a group.
	 */
	public static void deleteGroup(String userName)
	{
		System.out.print("Enter the groups name to delete: ");
		String gName = input.nextLine();
		boolean deleted = groupServ.deleteGroup(gName, (UserToken)groupServ.getToken(userName, keys.userKeys.getPublicKey(userName), keys.userKeys.getPrivateKey(userName),
							keys.userKeys.getServerKey(userName),  fileServerPublicKey).get(0));
		if(!deleted)
		{
			System.out.println("Unable to delete the group " + gName + ".");
		}
		else
		{
			System.out.println("The group " + gName + " has been deleted.");
		}
	}//end of deleteGroup
		
	
	/**
	 * Allows a user to create a new user in the system.
	 */
	public static void createNewUser(String userName)
	{
		System.out.print("Enter the new users username: ");
		String uName = input.nextLine();
		boolean user = keys.userKeys.addUser(uName, keys.userKeys.getServerKey(userName), keys.userKeys.getFileServerKey(userName));
		if(!user)
		{
			System.out.println("Unable to create keys for the user");
			return;
		}
		boolean created = groupServ.createUser(uName,(UserToken)groupServ.getToken(userName, keys.userKeys.getPublicKey(userName), 
					keys.userKeys.getPrivateKey(userName), keys.userKeys.getServerKey(userName), fileServerPublicKey).get(0), keys.userKeys.getPublicKey(uName));
		if(!created)
		{
			System.out.println("You do not have permission to create a new user and/or the username already exists");
			keys.userKeys.removeUser(uName);
		}
		else
		{
			System.out.println("The new user " + uName + " has been created.");
		}
	}//end of createNewUser
		
	/**
	 * This method lists the members of a group.
	 */
	public static void listMembers(String userName)
	{
		UserToken myToken = (UserToken)groupServ.getToken(userName, keys.userKeys.getPublicKey(userName), keys.userKeys.getPrivateKey(userName),
							keys.userKeys.getServerKey(userName), fileServerPublicKey).get(0);
		System.out.print("Enter the name of the group whose members you would like to display: ");
		String gName = input.nextLine();
		List <String> members = groupServ.listMembers(gName, myToken);
		if(members == null)
		{
			System.out.println("Unable to list the members of " + gName);
		}
		else
		{
			int j = 1;
			System.out.println(gName + "'s members: ");
			for(int i = 0; i < members.size(); i++)
			{
				System.out.println(j + ". " + members.get(i));
				j++;
			}
		}//end of else
	}//end of listMembers method
	
	
	/**
	 * This method allows a user to upload a file to the server
	 */
	public static void uploadFile(String userName) throws Exception
	 {
		 System.out.print("Enter the path to the file: ");
		 String path = input.nextLine();
		 System.out.print("Enter the filename to use on the server: ");
		 String fName = input.nextLine();
		 System.out.print("Enter the name of the group to share the file with: ");
		 String gName = input.nextLine();
		 ArrayList<Object> temp=groupServ.getToken(userName, keys.userKeys.getPublicKey(userName), 
			keys.userKeys.getPrivateKey(userName), keys.userKeys.getServerKey(userName), fileServerPublicKey);
		 UserToken theToken=(UserToken)temp.get(0);
		 groupKeys=(HashMap<String,ArrayList<SecretKey>>)temp.get(1);
		 ArrayList<SecretKey> keysForGroup=groupKeys.get(gName);
		 SecretKey latestKey=keysForGroup.get(keysForGroup.size()-1);
		 Cipher encrypter=Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
		 byte[] initVector= new BigInteger(128, new SecureRandom()).toByteArray(); //need to initialize, maybe encrypting already adds a random iv to front?
		 if(initVector.length>16) 
				initVector = java.util.Arrays.copyOfRange(initVector, 1, 17);
		 ByteBuffer converter=ByteBuffer.allocate(4);
		 converter.putInt(keysForGroup.size()-1);
		 byte[] encrVers=converter.array(); //turn int->byte->byte[], need better way
		 byte[] encrFile=Files.readAllBytes(Paths.get(path)); //turns string->path->file->byte[]
		 encrypter.init(Cipher.ENCRYPT_MODE,latestKey,new IvParameterSpec(initVector));
		 encrVers=encrypter.doFinal(encrVers); //encrypt version
		 encrFile=encrypter.doFinal(encrFile); //encrypt file
		 FileOutputStream tempFile=new FileOutputStream("temp_upload"); //write these bytes to temp file
		 tempFile.write(encrFile);
		 tempFile.close();
		 path="temp_upload";
		 boolean uploaded = fileServ.upload(path, fName, gName,theToken,keysForGroup.size()-1,encrVers,initVector);
		 if(!uploaded)
		 {
			 System.out.println("The file could not be successfully uploaded to the server.");
		 }
		 else
		 {
			 System.out.println("The file " + fName + " has been successfully uploaded to the file server "
							+ " and is visible to the " + gName + " group.");
		 }
		 File tempUpload=new File("temp_upload");
		 tempUpload.delete(); //delete temp file after operation
	}//end of uploadFile method
	 
	/**
	 * This method allows a user to download a file from the server
	 */
	public static void downloadFile(String userName) throws Exception
	{
		  System.out.print("Enter the name of the file you would like to download: ");
		  String sysName = input.nextLine();
		  System.out.print("Enter what name you would like to save the file as on your computer: ");
		  String fileName = input.nextLine();
		  ArrayList<Object> temp=groupServ.getToken(userName, keys.userKeys.getPublicKey(userName), 
			keys.userKeys.getPrivateKey(userName), keys.userKeys.getServerKey(userName), fileServerPublicKey);
		 UserToken theToken=(UserToken)temp.get(0);
		 groupKeys=(HashMap<String,ArrayList<SecretKey>>)temp.get(1);
		  ArrayList<Object> downloaded = fileServ.download(sysName, fileName, theToken);
		  if(downloaded==null)
		  {
			  System.out.println("The file could not be downloaded");
		  }
		  //need decrypt file by matching key and version
		  else
		  {
			  int version=(Integer)downloaded.get(0);
			  byte[] encryptedVersion=(byte[])downloaded.get(1); 
			  byte[] initVector=(byte[])downloaded.get(2);
			  String groupName=(String)downloaded.get(3);
			  ArrayList<SecretKey> keysForGroup=groupKeys.get(groupName);
			  SecretKey theKey=keysForGroup.get(version);
			  Cipher decrypter=Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			  decrypter.init(Cipher.DECRYPT_MODE,theKey,new IvParameterSpec(initVector));
			  encryptedVersion=decrypter.doFinal(encryptedVersion);
			  ByteBuffer converter=ByteBuffer.wrap(encryptedVersion);
			  int decryptedVers=converter.getInt(); //might be more complicated
			  if(decryptedVers!=version) //if not match delete downloaded file
			  {
				  System.out.println("Error, the file keys do not match.");
				  File delFile=new File(fileName);
				  delFile.delete();
			  }
			  else //decrypt the actual file
			  {
				  byte[] decryptFile=Files.readAllBytes(Paths.get(fileName));
				  decryptFile=decrypter.doFinal(decryptFile);
				  File delFile=new File(fileName);
				  delFile.delete();
				  FileOutputStream realFile=new FileOutputStream(fileName);
				  realFile.write(decryptFile);
				  realFile.close();
				  System.out.println("The file " + sysName + " has been successfully downloaded as " + fileName + ".");
			  }
		  }
	}//end of downloadFile method
	  
	/**
	 * This method allows a user to delete a file from the server
	 */
	public static void deleteFile(String userName)
	{
		System.out.print("Enter the name of the file you would like to delete: ");
		String fileName = input.nextLine();
		boolean deleted = fileServ.delete(fileName, (UserToken)groupServ.getToken(userName, keys.userKeys.getPublicKey(userName), keys.userKeys.getPrivateKey(userName),
							keys.userKeys.getServerKey(userName), fileServerPublicKey).get(0));
		if(!deleted)
		{
			System.out.println("The file could not be deleted.");
		}
		else
		{
			System.out.println("The file " + fileName + " has been deleted.");
		}
	}//end of deleteFile method
	
	/**
	 * This method allows a user to display the files from all the groups they belong to
	 */
	public static void displayFiles(String userName)
	{
		List <String> myfiles = fileServ.listFiles((UserToken)groupServ.getToken(userName, keys.userKeys.getPublicKey(userName), keys.userKeys.getPrivateKey(userName),
					keys.userKeys.getServerKey(userName), fileServerPublicKey).get(0));
		ListIterator<String> iterator = myfiles.listIterator();
		int i = 1;
		System.out.println(userName + "'s files: ");
		while(iterator.hasNext())
		{
			System.out.println(i + ". " + iterator.next());
			i++;
		}//end of wile loop
	}//end of displayFiles method
	 
	/**
	 * Allows a user to exit the system.
	 */
	public static void quit()
	{
		groupServ.disconnect();
		fileServ.disconnect();
		System.out.println("Goodbye!");
		
	}//end of the quit method

}//end of class

