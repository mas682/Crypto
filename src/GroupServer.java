/* Group server. Server loads the users from UserList.bin.
 * If user list does not exists, it creates a new list and makes the user the server administrator.
 * On exit, the server saves the user list to file.
 */


import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;
import java.util.*;
import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class GroupServer extends Server {

	public static final int SERVER_PORT = 8765;
	public UserList userList;
	public GroupList groupList;				//added in to hold groupList of server
	public KeyPair keys;				//used to hold the group servers public/private key

	public GroupServer() {
		super(SERVER_PORT, "ALPHA");
		Security.addProvider(new BouncyCastleProvider());
	}

	public GroupServer(int _port) {
		super(_port, "ALPHA");
		Security.addProvider(new BouncyCastleProvider());
	}

	public void save()
	{
		System.out.println("Saving...");
		ObjectOutputStream outStream;
		try{
			outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
			outStream.writeObject(this.userList);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
			outStream.writeObject(this.groupList);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
	
	

	public void start() {
		// Overwrote server.start() because if no user file exists, initial admin account needs to be created

		String userFile = "UserList.bin";
		Scanner console = new Scanner(System.in);
		ObjectInputStream userStream;
		ObjectInputStream groupStream;
		String username = null;
		Key publicKey;
		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListener(this));

		//Open user file to get user list
		try
		{
			FileInputStream fis = new FileInputStream(userFile);
			userStream = new ObjectInputStream(fis);
			userList = (UserList)userStream.readObject();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("UserList File Does Not Exist. Creating UserList...");
			System.out.println("No users currently exist. Your account will be the administrator.");
			System.out.print("Enter your username: ");
			username = console.next();

			//Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
			userList = new UserList();
			userList.addUser(username, null);
			userList.addGroup(username, "ADMIN");
			userList.addOwnership(username, "ADMIN"); 
		}
		catch(IOException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}
		
		String serverKeys = "groupKey.bin";
		//Open file to get servers keys
		try
		{
			FileInputStream fis = new FileInputStream(serverKeys);
			userStream = new ObjectInputStream(fis);
			keys = (KeyPair)userStream.readObject();
			//publicKey = keys.getPublic();
			//privateKey= keys.getPrivate();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("groupKey File Does Not Exist. Creating groupKey file...");

			//Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
			keys = generateKeys();
		}
		catch(IOException e)
		{
			System.out.println("Error reading from groupKey file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from groupKey file");
			System.exit(-1);
		}
		
		//print group server pub key
		System.out.println("Server public key:\n" + Utils.toHex(keys.getPublic().getEncoded()));

		String groupFile = "GroupList.bin";

		//Open group file to get group list
		try
		{
			FileInputStream fis = new FileInputStream(groupFile);
			groupStream = new ObjectInputStream(fis);
			groupList = (GroupList)groupStream.readObject();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("GroupList File Does Not Exist. Creating GroupList...");
			//Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
			if(username == null) username = console.next();
			groupList = new GroupList();
			groupList.addGroup("ADMIN", username);
			System.out.println(username + " added to ADMIN group.");
		}
		catch(IOException e)
		{
			System.out.println("Error reading from GroupList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from GroupList file");
			System.exit(-1);
		}
		//Autosave Daemon. Saves lists every 5 minutes
		AutoSave aSave = new AutoSave(this);
		aSave.setDaemon(true);
		aSave.start();
		//This block listens for connections and creates threads on new connections
		try
		{

			final ServerSocket serverSock = new ServerSocket(port);

			Socket sock = null;
			GroupThread thread = null;
			while(true)
			{
				sock = serverSock.accept();
				thread = new GroupThread(sock, this);
				thread.start();
				
			}
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}

	}
	
	private KeyPair generateKeys()
	{
		Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator key = null;
		KeyPair serverKeys = null;
		//generate keys
		try{
			key = KeyPairGenerator.getInstance("RSA", "BC");		//generate a key pair for RSA using bouncycastle
			key.initialize(2048);									//initialize the key size to 2048
			serverKeys = key.generateKeyPair();
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
		return serverKeys;
	}

}		
	

	

//This thread saves the user list
class ShutDownListener extends Thread
{
	public GroupServer my_gs;

	public ShutDownListener (GroupServer _gs) {
		my_gs = _gs;
	}

	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;
		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
			outStream.writeObject(my_gs.userList);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
			outStream.writeObject(my_gs.groupList);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("groupKey.bin"));
			outStream.writeObject(my_gs.keys);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		
	}
}

class AutoSave extends Thread
{
	public GroupServer my_gs;

	public AutoSave (GroupServer _gs) {
		my_gs = _gs;
	}

	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave group and user lists ...");
				ObjectOutputStream outStream;
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
					outStream.writeObject(my_gs.userList);
					outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
					outStream.writeObject(my_gs.groupList);
					outStream = new ObjectOutputStream(new FileOutputStream("groupKey.bin"));
					outStream.writeObject(my_gs.keys);
					
				}
				catch(Exception e)
				{
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}

			}
			catch(Exception e)
			{
				System.out.println("Autosave Interrupted");
			}
			
		} while(true);
	}
}
