import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;

public class MainClass {

	public static void main(final String[] args) {
		User alice = new User();
		User bob = new User();
		String key=Common.generateKeyString();
		String pt = "02 13 24 35 46 57 68 79 8a 9b ac bd ce df e0 f1";
		/////////////////////////////////////////////////////////////////////////
		//					passing the key safely from alice to bob           //
		/////////////////////////////////////////////////////////////////////////
		
		/*bob decides about public and private keys and then he publishes only the public key*/
		bob.generate_public_key();
		
		/*alice gets public key */
		
		alice.generate_public_key(bob.getPublic_key_e(),bob.getPublic_key_n());
		
		/*alice gets the symmetric key and encrypts it by A-Symmetric algorithm RSA*/
		
		alice.setS_key(key);
		byte[] originalMessage=alice.getS_key();
		
		byte[] cipher=alice.getRsa().encrypt(alice.getS_key());
		
		//alice uses a RSA type Digital Signature
		
		byte [] merged=alice.signMessage(originalMessage,cipher);
		
		//happens here since it has to happen after the sign of the message
		
		bob.setSizeOfKey(alice.getSizeOfKey());
		
		
		boolean messageWasNotForged=bob.VerifyMessage(merged);
		if( messageWasNotForged) {
			System.out.println("Sender authenticated\n");
			System.out.println("Performing Decryption\n");
			
			/*bob receives key decipher it and keep it to himself!*/
			
			bob.setS_key(bob.getRsa().decrypt(cipher));
			
			/////////////////////////////////////////////////////////////////////////
			//					alice encrypts a message and bob decipher it        //
			/////////////////////////////////////////////////////////////////////////		
					
			
			alice.setPlain_text(pt);
			
			
			bob.setCipher_text(alice.getRc6().encryption(alice.getPlain_text()));
				
			
		
			
			byte[] Message=bob.getRc6().decryption(bob.getCipher_text());
			
			
			System.out.println("The Message is "+Common.byteArrayToHex(Message));
			
		}else {
			System.out.println("The Message was forged!!!\n");
			
		}
		

		
		
		
	}

}
