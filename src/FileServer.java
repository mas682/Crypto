/* FileServer loads files from FileList.bin.  Stores files in shared_files directory. */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.Scanner;
import javax.crypto.*;
import java.security.spec.RSAPublicKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
public class FileServer extends Server {
	
	public static final int SERVER_PORT = 4321;
	public FileList fileList;
	public KeyPair keys;			//used to hold the group servers public/private key
	public Key publicGroup;

	public FileServer() {
		super(SERVER_PORT, "FilePile");
		Security.addProvider(new BouncyCastleProvider());
	}

	public FileServer(int _port) {
		super(_port, "FilePile");
		Security.addProvider(new BouncyCastleProvider());
	}
	
	
	
	public void start() {
		
		String fileFile = "FileList.bin";
		ObjectInputStream fileStream;
		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		Thread catchExit = new Thread(new ShutDownListenerFS(this));
		runtime.addShutdownHook(catchExit);
		
		//Open user file to get user list
		try
		{
			FileInputStream fis = new FileInputStream(fileFile);
			fileStream = new ObjectInputStream(fis);
			fileList = (FileList)fileStream.readObject();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("FileList Does Not Exist. Creating FileList...");
			
			fileList = new FileList();
			
		}
		catch(IOException e)
		{
			System.out.println("Error reading from FileList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from FileList file");
			System.exit(-1);
		}
		
		
		String fileServerKeys = "FileServerKeyPair.bin";
		//open file to get the file servers keys
		try
		{
			FileInputStream fis = new FileInputStream(fileServerKeys);
			fileStream = new ObjectInputStream(fis);
			keys = (KeyPair)fileStream.readObject();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("FileServerKeyPair file does not exist.  Creating FileServerKeyPair file...");
			//create the keys
			keys = generateKeys();
		}
		catch(IOException e)
		{
			System.out.println("Error reading from FileServerKeyPair file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from FileServerKeyPair file");
			System.exit(-1);
		}
		
		
		
		File file = new File("shared_files");
		if (file.mkdir()) {
			System.out.println("Created new shared_files directory");
		}
		else if (file.exists()){
			System.out.println("Found shared_files directory");
		}
		else {
			System.out.println("Error creating shared_files directory");		
		}
		String publicKey="groupPubKey.bin";
		try
		{
			FileInputStream fis = new FileInputStream(publicKey);
			fileStream = new ObjectInputStream(fis);
			publicGroup = (Key)fileStream.readObject();
			//publicKey = keys.getPublic();
			//privateKey= keys.getPrivate();
		}
		catch(Exception e) {
			e.printStackTrace();
		}
		
		//Autosave Daemon. Saves lists every 5 minutes
		AutoSaveFS aSave = new AutoSaveFS(this);
		aSave.setDaemon(true);
		aSave.start();
		
		
		boolean running = true;
		
		try
		{			
			final ServerSocket serverSock = new ServerSocket(port);
			System.out.printf("%s up and running\n", this.getClass().getName());
			
			Socket sock = null;
			Thread thread = null;
			
			while(running)
			{
				sock = serverSock.accept();
				thread = new FileThread(sock,this);
				thread.start();
			}
			
			System.out.printf("%s shut down\n", this.getClass().getName());
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
	
	//this method generates a key pair for the file server
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

//This thread saves user and group lists
class ShutDownListenerFS implements Runnable
{
	public FileServer my_fs;

	public ShutDownListenerFS (FileServer _fileServer) {
		my_fs =_fileServer;
	}
	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;

		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
			outStream.writeObject(my_fs.fileList);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("groupPubKey.bin"));
			outStream.writeObject(my_fs.publicGroup);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("FileServerKeyPair.bin"));
			outStream.writeObject(my_fs.keys);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSaveFS extends Thread
{
	public FileServer my_fs;
	
	public AutoSaveFS(FileServer _fs)
	{
		my_fs = _fs;
	}
	
	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave file list...");
				ObjectOutputStream outStream;
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
					outStream.writeObject(my_fs.fileList);
					outStream = new ObjectOutputStream(new FileOutputStream("FileServerKeyPair.bin"));
					outStream.writeObject(my_fs.keys);
					outStream = new ObjectOutputStream(new FileOutputStream("groupPubKey.bin"));
					outStream.writeObject(my_fs.publicGroup);
		
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
		}while(true);
	}
}
