/* This list represents the users on the server */
import java.util.*;
import java.security.*;

//Matt Stropkey

	public class UserList implements java.io.Serializable {
	
		/**
		 * 
		 */
		private static final long serialVersionUID = 7600343803563417990L;
		private Hashtable<String, User> list = new Hashtable<String, User>();
		
		
		public synchronized void addUser(String username, Key publicKey)
		{
			User newUser = new User(publicKey);
			list.put(username, newUser);
		}
		
		public synchronized void deleteUser(String username)
		{
			list.remove(username);
		}
		
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
		
		public synchronized ArrayList<String> getUserGroups(String username)
		{
			return list.get(username).getGroups();
		}
		
		public synchronized ArrayList<String> getUserOwnership(String username)
		{
			return list.get(username).getOwnership();
		}
		
		public synchronized void addGroup(String user, String groupname)
		{
			list.get(user).addGroup(groupname);
		}
		
		public synchronized void removeGroup(String user, String groupname)
		{
			list.get(user).removeGroup(groupname);
		}
		
		public synchronized void addOwnership(String user, String groupname)
		{
			list.get(user).addOwnership(groupname);
		}
		
		public synchronized void removeOwnership(String user, String groupname)
		{
			list.get(user).removeOwnership(groupname);
		}
		
		public synchronized void setUserKey(String user, Key pubKey)
		{
			list.get(user).setKey(pubKey);
		}
		
		public synchronized Key getKey(String user)
		{
			System.out.println("inside get key");
			return list.get(user).getKey();
		}
			
	
	class User implements java.io.Serializable {

		/**
		 * 
		 */
		private static final long serialVersionUID = -6699986336399821590L;
		private ArrayList<String> groups;
		private ArrayList<String> ownership;
		private Key publicKey;
		
		public User(Key pubKey)
		{
			if(pubKey == null)
			{ 
				publicKey = null;
			}
			else
			{
				publicKey = pubKey;
			}
			groups = new ArrayList<String>();
			ownership = new ArrayList<String>();
		}
		
		public void setKey(Key pubKey)
		{
			publicKey = pubKey;
		}
		public Key getKey()
		{
			if(publicKey == null)
			{
				System.out.println("public key null");
			}
			return publicKey;
		}
		
		public ArrayList<String> getGroups()
		{
			return groups;
		}
		
		public ArrayList<String> getOwnership()
		{
			return ownership;
		}
		
		public void addGroup(String group)
		{
			groups.add(group);
		}
		
		public void removeGroup(String group)
		{
			if(!groups.isEmpty())
			{
				if(groups.contains(group))
				{
					groups.remove(groups.indexOf(group));
				}
			}
		}
		
		public void addOwnership(String group)
		{
			ownership.add(group);
		}
		
		public void removeOwnership(String group)
		{
			if(!ownership.isEmpty())
			{
				if(ownership.contains(group))
				{
					ownership.remove(ownership.indexOf(group));
				}
			}
		}
		
		
	}
	
}	
