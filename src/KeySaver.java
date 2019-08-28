//This class will be used to save the users keys
//Matt Stropkey
import java.io.*;
import java.util.*;



//this class is used start up a file that stores the user's keys to test the application
//the keys are stored in userKeys


public class KeySaver {
	
	public UserKeys userKeys;	//used to hold each users keys
	private boolean initialization;	//used if this is the first time running the app
	//may have an issue here...
	
	public void save()
	{
		//System.out.println("Saving...");
		ObjectOutputStream outStream;
		try{
			outStream = new ObjectOutputStream(new FileOutputStream("UserKeys.bin"));
			outStream.writeObject(this.userKeys);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
	
	public void start()
	{
		//set the name of the file to UserKeys.bin
		String userKeyFile = "UserKeys.bin";
		Scanner console = new Scanner(System.in);
		ObjectInputStream userKeyStream;
		String username = null;
		//This runs a thread that saves the Keys on program exit
		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListener(this));
		initialization = false;

		//Open userKeyFile to get userKey list
		try
		{
			FileInputStream fis = new FileInputStream(userKeyFile);
			userKeyStream = new ObjectInputStream(fis);
			userKeys = (UserKeys)userKeyStream.readObject();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("UserKeys File Does Not Exist. Creating UserKeys...");
			System.out.println("No user keys currently exist.");
			System.out.print("Enter your username that you have used for the group server: ");
			username = console.next();
			//create a new userKey list, generate a key for them
			userKeys = new UserKeys();
			userKeys.addUser(username, null, null);
			initialization = true;
		}
		catch(IOException e)
		{
			System.out.println("Error reading from UserKeys file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from UserKeys file");
			System.exit(-1);
		}
		
		//Autosave Daemon. Saves lists every 5 minutes
		AutoSave aSave = new AutoSave(this);
		aSave.setDaemon(true);
		aSave.start();
	}
	
	public boolean init()
	{
		return initialization;
	}




//This thread saves the user list
class ShutDownListener extends Thread
{
	public KeySaver my_keys;

	public ShutDownListener (KeySaver keys) {
		my_keys = keys;
	}

	public void run()
	{
		//System.out.println("Shutting down KeySaver");
		ObjectOutputStream outStream;
		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("UserKeys.bin"));
			outStream.writeObject(my_keys.userKeys);
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
	public KeySaver my_keys;

	public AutoSave (KeySaver keys) {
		my_keys = keys;
	}

	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				//System.out.println("Autosave user keys ...");
				ObjectOutputStream outStream;
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("UserKeys.bin"));
					outStream.writeObject(my_keys.userKeys);
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

}