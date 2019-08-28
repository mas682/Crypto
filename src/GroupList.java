/* This list represents the groups on the server */
import java.util.*;
import java.security.*;
import javax.crypto.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

//Matt Stropkey

	public class GroupList implements java.io.Serializable {
	
		/**
		 * 
		 */
		 
		 //need to change ID
		private static final long serialVersionUID = 7600343803563017992L;
		private Hashtable<String, Group> list = new Hashtable<String, Group>();
		
		public synchronized ArrayList<SecretKey> getKeys(String groupName)
		{
			return list.get(groupName).getKeys();
		}
		public synchronized void addGroup(String groupName, String userName)
		{
			Group newGroup = new Group(userName);
			list.put(groupName, newGroup);
		}
		
		public synchronized void deleteGroup(String groupName)
		{
			list.remove(groupName);
		}
		
		public synchronized boolean checkGroup(String groupName)
		{
			if(list.containsKey(groupName))
			{
				return true;
			}
			else
			{
				return false;
			}
		}
		
		public synchronized ArrayList<String> getGroupMembers(String groupName)
		{
			return list.get(groupName).getGroupMembers();
		}
		
		public synchronized ArrayList<String> getGroupOwnership(String groupName)
		{
			return list.get(groupName).getOwnership();
		}
		
		public synchronized void addUser(String groupName, String userName)
		{
			list.get(groupName).addToGroup(userName);
			list.get(groupName).generateNewKey();
		}
		
		public synchronized ArrayList<String> removeGroup(String groupName)
		{
			ArrayList<String> temp = list.get(groupName).removeGroup(groupName);
			list.remove(groupName);
			return temp;
		}
		
		public synchronized void addOwnership(String user, String groupName)
		{
			list.get(groupName).addOwnership(user);
		}
		
		public synchronized void removeOwnership(String user, String groupName)
		{
			list.get(groupName).removeOwnership(user);
		}
		
		public synchronized void removeMember(String user, String groupName)
		{
			list.get(groupName).removeMember(user);
			list.get(groupName).generateNewKey();
			
		}
		
	
	class Group implements java.io.Serializable {

		 
		 //need to change ID
		private static final long serialVersionUID = -6699986336399821598L;
		private ArrayList<String> members;
		private ArrayList<String> ownership;
		//private KeyGenerator generator;
		private ArrayList<SecretKey> keys; //need better way to differentiate keys of multiple groups
		public Group(String userName)
		{
			Security.addProvider(new BouncyCastleProvider());
			members = new ArrayList<String>();
			ownership = new ArrayList<String>();
			keys=new ArrayList<SecretKey>();
			try
			{
			KeyGenerator generator=KeyGenerator.getInstance("AES","BC");
			generator.init(256);
			members.add(userName);
			ownership.add(userName);
			SecretKey initKey=generator.generateKey();
			keys.add(initKey);
			byte[] read = initKey.getEncoded();
			System.out.println("GROUP KEY: " + read.toString());
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
		public ArrayList<SecretKey> getKeys()
		{
			return keys;
		}
		public void generateNewKey()
		{
			try{
			KeyGenerator generator=KeyGenerator.getInstance("AES","BC");
			generator.init(256);
			SecretKey newKey=generator.generateKey();
			keys.add(newKey);
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
		public ArrayList<String> getGroupMembers()
		{
			return members;
		}
		
		public ArrayList<String> getOwnership()
		{
			return ownership;
		}
		
		public void addToGroup(String userName)
		{
			members.add(userName);
		}
		
		//should return null if the group does not exist
		public ArrayList<String> removeGroup(String group)
		{
			ArrayList<String> temp = new ArrayList<>();
			//copy the group members to temp
			if(!members.isEmpty())
			{
				for(int i = 0; i < members.size(); i++)
				{
					temp.add(members.get(i));
				}
				members = null;
				ownership = null;
			}
			return temp;
		}
		
		public void removeMember(String userName)
		{
			if(!members.isEmpty())
			{
				if(members.contains(userName))
				{
					members.remove(userName);
				}
				if(!ownership.isEmpty())
				{
					if(ownership.contains(userName))
					{
						ownership.remove(userName);
					}
				}
			}
		}
		
		public void addOwnership(String userName)
		{
			ownership.add(userName);
		}
		
		public void removeOwnership(String userName)
		{
			if(!ownership.isEmpty())
			{
				if(ownership.contains(userName))
				{
					ownership.remove(ownership.indexOf(userName));
				}
			}
		}
		
	}
	
}	
