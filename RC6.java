	import java.util.Scanner;
	import java.io.BufferedReader;
	import java.io.BufferedWriter;
	import java.io.FileReader;
	import java.io.FileWriter;
	import java.io.IOException;

public class RC6 {	
	private static  int w = 32;
	private static final int r = 20;
	private static  int Pw = 0xb7e15163;
	private static  int Qw = 0x9e3779b9;
	
	private  int[] S;
	private byte[] key;
	
	public void setKey(byte[] key) {
		this.key = key;
		S = KeySchedule();
	}
	public byte[] getKey() {
		return this.key;
	}
	
	//Convert hexadecimal to byte array
	 static byte[] hexStringToByteArray(String s) {
		int string_len = s.length();
		byte[] data = new byte[string_len / 2];
		for (int i = 0; i < string_len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character
					.digit(s.charAt(i + 1), 16));
		}
		return data;
	}
	 //Convert the byte array to string in hex format
	private static String byteArrayToHex(byte[] a) {
		StringBuilder sb = new StringBuilder(a.length * 2);
		for (byte b : a)
			sb.append(String.format("%02x", b & 0xff));
		return sb.toString();
	}
	//Convert int to byte arrat
	private static byte[] convertIntToByte(int[] integerArray,int length){
		byte[]  int_to_byte=new byte[length];
		for(int i = 0;i<length;i++){
			int_to_byte[i] = (byte)((integerArray[i/4] >>> (i%4)*8) & 0xff);
		}	
		return int_to_byte;
	}
	
	//Convert byte to int 
	private static int[] convertBytetoInt(byte[] arr,int length){
		int[]  byte_to_int=new int[length];
		for(int j=0; j<byte_to_int.length; j++)
		{
			byte_to_int[j] = 0;
		}
		int counter = 0;
		for(int i=0;i<byte_to_int.length;i++){
			byte_to_int[i] = ((arr[counter++]&0xff))|
							 ((arr[counter++]&0xff) << 8) |
						     ((arr[counter++]&0xff) << 16) |
						     ((arr[counter++]&0xff) << 24);
		}
		return byte_to_int;
	}	
	//Convert byte array to words
	private static int[] bytestoWords(byte[] userkey,int c) {
		int[] bytes_to_words = new int[c];
		for (int i = 0; i < bytes_to_words.length; i++)
			bytes_to_words[i] = 0;

		for (int i = 0, off = 0; i < c; i++)
			bytes_to_words[i] = ((userkey[off++] & 0xFF)) | ((userkey[off++] & 0xFF) << 8)
					| ((userkey[off++] & 0xFF) << 16) | ((userkey[off++] & 0xFF) << 24);
		
		return bytes_to_words;
	}
	//Rotate left
	private static int rotateLeft(int val, int pas) {
		return (val << pas) | (val >>> (32 - pas));
	}
	
	//Rotate right
	private static int rotateRight(int val, int pas) {
		return (val >>> pas) | (val << (32-pas));
	}	
	
	//Key expansion algorithm
	private int[] KeySchedule() {				
		int[] S = new int[2 * r + 4];
		S[0] = Pw;	
		int c = this.key.length / (w/8);
		int[] L = bytestoWords(this.key,  c);		
		for (int i = 1; i < (2 * r + 4); i++){
			S[i] = S[i - 1] + Qw;
		}
					
		int A,B,i,j;		
		A=B=i=j=0;
		int v = 3 * Math.max(c, (2 * r + 4));
		for (int s = 0; s < v; s++) {
			A = S[i] = rotateLeft((S[i] + A + B), 3);
			B = L[j] = rotateLeft(L[j] + A + B, A + B);
			i = (i + 1) % (2 * r + 4);
			j = (j + 1) % c;
		}
		return S;
	}	
	
	//Encryption algoritm
	public byte[] encryption(byte[] keySchArray){	
		int temp,t,u;
		int[] temp_data = new int[keySchArray.length/4];
		for(int i =0;i<temp_data.length;i++)
			temp_data[i] = 0;
		temp_data=convertBytetoInt(keySchArray,temp_data.length);	
		int A,B,C,D;
		A=B=C=D=0;
		
		A = temp_data[0];
		B = temp_data[1];
		C = temp_data[2];
		D = temp_data[3];
		B = B + S[0];
		D = D + S[1];
		int lgw=5;
		byte[] outputArr = new byte[keySchArray.length];
		for(int i = 1;i<=r;i++){		
			t = rotateLeft(B*(2*B+1),lgw);			
			u = rotateLeft(D*(2*D+1),lgw);			
			A = rotateLeft(A^t,u)+S[2*i];			
			C = rotateLeft(C^u,t)+S[2*i+1];	
			temp = A;
			A = B;
			B = C;
			C = D;
			D = temp;
		}
		A = A + S[2*r+2];
		C = C + S[2*r+3];
		temp_data[0] = A;
		temp_data[1] = B;
		temp_data[2] = C;
		temp_data[3] = D;
		outputArr = convertIntToByte(temp_data,keySchArray.length);
		return outputArr;
	}
	//Decipher algorithm
	public byte[] decryption(byte[] keySchArray){
		int temp,t,u;
		int A,B,C,D;
		A=B=C=D=0;
		int[] temp_data_decryption = new int[keySchArray.length/4];
		for(int i =0;i<temp_data_decryption.length;i++)
			temp_data_decryption[i] = 0;
		temp_data_decryption=convertBytetoInt(keySchArray,temp_data_decryption.length);
		A = temp_data_decryption[0];
		B = temp_data_decryption[1];
		C = temp_data_decryption[2];
		D = temp_data_decryption[3];
		C = C - S[2*r+3];
		A = A - S[2*r+2];
		int lgw=5;
		byte[] outputArr = new byte[keySchArray.length];
		for(int i = r;i>=1;i--){
			temp = D;
			D = C;
			C = B;
			B = A;
			A = temp;
			u = rotateLeft(D*(2*D+1),lgw);	
			t = rotateLeft(B*(2*B+1),lgw);			
			C= rotateRight(C-S[2*i+1],t)^u;	
			A= rotateRight(A-S[2*i], u)^t;
		}
		D=D-S[1];
		B=B-S[0];
		temp_data_decryption[0] = A;
		temp_data_decryption[1] = B;
		temp_data_decryption[2] = C;
		temp_data_decryption[3] = D;
		outputArr = convertIntToByte(temp_data_decryption,keySchArray.length);
		return outputArr;
	}
	
	
	
	
	
	
}
