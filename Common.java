import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;

public class Common {

	// CODE TO CONVERT HEXADECIMAL NUMBERS IN STRING TO BYTE ARRAY
		public static byte[] hexStringToByteArray(String s) {
			int string_len = s.length();
			byte[] data = new byte[string_len / 2];
			for (int i = 0; i < string_len; i += 2) {
				data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
			}
			return data;
		}
		 
		// CODE TO CONVERT BYTE ARRAY TO HEX FORMAT
		public static String byteArrayToHex(byte[] a) {
			StringBuilder sb = new StringBuilder(a.length * 2);
			for (byte b : a)
				sb.append(String.format("%02x", b & 0xff));
			return sb.toString();
		}

		public static BigInteger hashCode(String s) {
			BigInteger value = new BigInteger(s, 16);
			String val="31";
			BigInteger value2 = new BigInteger(val,10);
			String val2="37";
			value.multiply(value2);
			BigInteger value4 = new BigInteger(val2,10);
			value.multiply(value4);
			return value;
		}
		
		public static String generateKeyString()
		{
			Scanner input = new Scanner(System.in);
			String key="";
			Random random = new Random();
			int r,num,i,bytes=16;
			
			
			System.out.println("Please enter "+bytes/2+" numbers:");
			for(i=0;i<bytes*2;i++)
			{
				if(i%4==0)
				{
					System.out.print("Enter "+(i/4+1)+" number:");
					num=input.nextInt();	
					random.setSeed(System.currentTimeMillis()+num);
				}
				r=random.nextInt(16);
				if(r<=9)
					key+=""+r+"";
				else
					key+=(char)('a'+(r-10));
					
			}
			System.out.println(key+"\n");
			return key;
		}
}