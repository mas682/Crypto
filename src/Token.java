


import java.util.ArrayList;
import java.util.List;
import java.security.MessageDigest;
import java.security.*;
//Jonathan Zhang
//CS 1653
//Phase 2
public class Token implements UserToken, java.io.Serializable
{
    private static final long serialVersionUID = 1653L;
	private String issuer;
	private String subject;
	private ArrayList<String> groups;
	private Key fileKey;
	private byte[] signature;
	public Token()
	{
		this(null,null, null);
	}
	
	public Token(String issuer,String subject,ArrayList<String> groups, Key fileKey)
	{
		this.issuer=issuer;
		this.subject=subject;
		this.groups=groups;
		this.signature=null;
		this.fileKey = fileKey;
	}
	
	public Token(String issuer,String subject, Key fileKey)
	{
		this(issuer,subject,new ArrayList<String>(), fileKey);
	}
	
	public String getIssuer()
	{
		return issuer;
	}

	public String getSubject()
	{	
		return subject;
	}
	public ArrayList<String> getGroups()
	{
		return groups;
	}
	public Key getFileKey()
	{
		return fileKey;
	}
	
	public boolean removeGroup(String groupName)
	{
		return groups.remove(groupName);
	}
	public byte[] getSignature()
	{
		return signature;
	}
	public void setSignature(byte[] newSignature)
	{
		signature=newSignature;
	}
	public String toString()
	{
		String returnedString="#0"+this.getIssuer();
		returnedString+="#1"+this.getSubject();
		ArrayList<String> temp=this.getGroups();
		returnedString+="#2"+temp.size();
		int groupCounter=3;
		for(String group:temp)
			returnedString+="#"+(groupCounter++)+group;
		return returnedString;
	}
}
 
