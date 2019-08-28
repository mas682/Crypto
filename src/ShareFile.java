public class ShareFile implements java.io.Serializable, Comparable<ShareFile> {

	/**
	 * 
	 */
	private static final long serialVersionUID = -6699986336399821598L;
	private String group;
	private String path;
	private String owner;
	private int keyVersion;
	private byte[] encrVers;
	private byte[] iv;
	public ShareFile(String _owner, String _group, String _path,int version,byte[] encrVers,byte[] initVector) {
		group = _group;
		owner = _owner;
		path = _path;
		keyVersion=version;
		this.encrVers=encrVers;
		iv=initVector;
	}
	
	public String getPath()
	{
		return path;
	}
	
	public String getOwner()
	{
		return owner;
	}
	
	public String getGroup() {
		return group;
	}
	public int getKeyVersion()
	{
		return keyVersion;
	}
	public byte[] getEncryptedKey()
	{
		return encrVers;
	}
	public byte[] getIV()
	{
		return iv;
	}
	public int compareTo(ShareFile rhs) {
		if (path.compareTo(rhs.getPath())==0)return 0;
		else if (path.compareTo(rhs.getPath())<0) return -1;
		else return 1;
	}
	
	
}	
