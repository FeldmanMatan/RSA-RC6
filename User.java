import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.*;
import java.util.Arrays;
public class User {
	private BigInteger public_key_e;	
	private BigInteger public_key_n;
	private byte[] s_key; 
	private RC6 rc6;
	private RSA rsa;
	private byte[] plain_text;
	private byte[] cipher_text;
	private int sizeOfKey;
	
	public int getSizeOfKey() {
		return sizeOfKey;
	}

	public void setSizeOfKey(int sizeOfKey) {
		this.sizeOfKey = sizeOfKey;
	}

	User ( ) {
		rc6= new RC6();
	}
	
	public RSA getRsa() {
		return rsa;
	}

	public RC6 getRc6() {
		return rc6;
	}

	public BigInteger getPublic_key_e() {
		return public_key_e;
	}
	public void setPublic_key_e(BigInteger public_key_e) {
		this.public_key_e = public_key_e;
	}
	public byte[] getCipher_text() {
		return cipher_text;
	}

	public void setCipher_text(byte[] cipher_text) {
		this.cipher_text = cipher_text;
	}

	public BigInteger getPublic_key_n() {
		return public_key_n;
	}
	public void setPublic_key_d(BigInteger public_key_n) {
		this.public_key_n = public_key_n;
	}
	
	public byte[] getPlain_text() {
		return this.plain_text;
	}
	
	
	public void setPlain_text(byte[] pt) {
		this.plain_text = pt;
	}
	public void setPlain_text(String pt) {
		String temp = pt.replace(" ", "");
		this.plain_text = Common.hexStringToByteArray(temp);
	}

	public  byte[] getS_key() {
		return this.getRc6().getKey();
	}
	public void setS_key(String s_key){
		String temp = s_key.replace(" ", "");
		this.getRc6().setKey(Common.hexStringToByteArray(temp)); 
	}
	public void setS_key(byte[] s_key) {
		this.getRc6().setKey(s_key);
	}
	
	public void generate_public_key() {
		this.rsa = new RSA();
		this.public_key_e = rsa.getE();
		this.public_key_n = rsa.getN();
	}
	
	public void generate_public_key(BigInteger public_key_e,BigInteger public_key_n) {
		this.rsa = new RSA(public_key_e,public_key_n);
		this.public_key_e =	public_key_e;
		this.public_key_n = public_key_n;
	}
	
	public byte[] signMessage(byte[] originalMessage,byte[] cipher) {
		
		
		BigInteger intRepresentationOfHash=Common.hashCode(Common.byteArrayToHex(originalMessage));
		byte[] bytesOfkey= intRepresentationOfHash.toByteArray();

		byte[] bytesOfkeyEncrypted=this.getRsa().encrypt(bytesOfkey);
		
		byte[] merged=new byte[cipher.length+bytesOfkeyEncrypted.length];
		int i;
		
		setSizeOfKey(cipher.length);
		
		for(i=0;i<cipher.length;i++) {
			merged[i]=cipher[i];
		}
		
		for(byte x:bytesOfkeyEncrypted) {
			merged[i]=x;
			i++;
		}
		return merged;
	}

	
	public boolean VerifyMessage(byte[] message) {
		
		byte[] cipherKey=new byte[this.getSizeOfKey()];
		int k,i=0;
		for(k=0;k<this.getSizeOfKey();k++) {
			cipherKey[k]=message[k];
		}
		
		int sizeOfSignature=message.length-this.getSizeOfKey();
		
		byte[] signature=new byte[sizeOfSignature];
		
		
		while(k<message.length) {
			signature[i]=message[k];
			k++;
			i++;
		}
		//Decipher the key and turn into hash code 
		byte[] decyphredKey=this.getRsa().decrypt(cipherKey);
		BigInteger hashValueOfKey=Common.hashCode(Common.byteArrayToHex(decyphredKey));
		byte[] bytesOfkey=hashValueOfKey.toByteArray();
				
		
		
		//Decipher 
		byte[] decyphredSignature=this.getRsa().decrypt(signature);
		

		return Arrays.equals(bytesOfkey,decyphredSignature);
		
		
	}
}
