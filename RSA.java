import java.math.BigInteger;
import java.util.Random;

public class RSA {
	private static final int bitlength = 1024;
	private BigInteger p;
    private BigInteger q;
    private BigInteger n;
    private BigInteger e;
    private BigInteger d;
    private BigInteger phi;
    
   
    public RSA() {
   	 	Random rnd = new Random();
        p = BigInteger.probablePrime(bitlength, rnd);
        q = BigInteger.probablePrime(bitlength, rnd);
        while (p==q) {
        	q = BigInteger.probablePrime(bitlength, rnd);
        }/*end while*/
        this.n = p.multiply(q);
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));//phi=(p-1)(q-1)
        e = BigInteger.probablePrime(bitlength / 2, rnd);//choose e 
        while (phi.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(phi) < 0)
        {
            e.add(BigInteger.ONE);
        }
        d = e.modInverse(phi);
   }
   
   public RSA(BigInteger e, BigInteger n)
   {
       this.e = e;
       this.n = n;
       this.d = BigInteger.ZERO;
       this.p =	BigInteger.ZERO;
       this.q = BigInteger.ZERO;
   }    
    
	public BigInteger getN() {
		return this.n;
	}

	public void setN(BigInteger n) {
		this.n = n;
	}

	public BigInteger getE() {
		return this.e;
	}

	public void setE(BigInteger e) {
		this.e = e;
	}
	
    private static String bytesToString(byte[] encrypted)
    {
        String test = "";
        for (byte b : encrypted)
        {
            test += Byte.toString(b);
        }
        return test;
    }
    // Encrypt message
    public byte[] encrypt(byte[] message)
    {
        return (new BigInteger(message)).modPow(e, n).toByteArray();
    }
    // Decipher message
    public byte[] decrypt(byte[] message)
    {
    	if (d.equals(BigInteger.ZERO) || p.equals(BigInteger.ZERO) || q.equals(BigInteger.ZERO) )
    	{
    		System.out.println("can't decrypt!- privare key not availbale!");
    		return(null);
    	}
        return (new BigInteger(message)).modPow(d, n).toByteArray();
    }
    
    
}
