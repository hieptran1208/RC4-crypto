package proj2;

// Hiep Tran
// Project 2- RC4 implementation
// Contribution: Nhu Luong explained to me the question. 
// 	Specifically, Nhu Luong told me the functionalities of the crack method and the crackedtext method in an overall picture

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * cracks weakened ARC4 keys. we know all cipher text has been encrypted with
 * a 11 byte ARC4 key. we also know that the first 8 bytes of the key are:
 * 0x1337d00d1550c001
 *
 * each instance of this class represents a ARC4 key to be discovered. all hints
 * about cracked text and requests to crack will be for cipher text encrypted
 * with the same key.
 */
public class ARC4Cracker {
    /**
     * the know prefix. (we just need to discover the remaining 3 bytes)
     */
    static public byte keyPrefix[] = { 0x13, 0x37, (byte)0xd0, 0x0d, 0x15, 0x50, (byte)0xc0, 0x01};
    
    static public boolean hint = false;
    static public byte[] keyStream = new byte[30];
    /**
     * this method provides a hint of known plaintext, and the corresponding cipherText
     * @param base64CipherText
     * @param base64PlainText base64 encoded known plain text from
     * @param position the position in the stream where the text was known
     */
    public void crackedText(String base64CipherText, String base64PlainText, int position) 
    { 
    	String cipher = new String(Base64.getDecoder().decode(base64CipherText));
    	String plainText = new String(Base64.getDecoder().decode(base64PlainText));
    	byte[] cp = cipher.getBytes();
    	byte[] pt = plainText.getBytes();
       			
		// XOR to get the key stream
		for (int i = position; i < cipher.length(); i++) 
		{
            keyStream[i] = (byte)(cp[i] ^ pt[i]);	
        }
		hint = true;
    }

    /**
     * the method will crack cipher text by searching for the correct plain text containing
     * the known string
     * @param base64CipherText base64 encoded cipher text to crack
     * @param base64KnownText a base64 encoded string that is know to exist in the plain text
     * @return the base64 encoded plain text or null if couldn't crack
     */
    public String crack(String base64CipherText, String base64KnownText) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException 
    { 
    	String result = null;
    	// change the base64 strings to normal strings
    	String cipherText = new String(Base64.getDecoder().decode(base64CipherText));
    	String knowText = new String(Base64.getDecoder().decode(base64KnownText));

    	// if there is some cracked text already
    	if(hint)
    	{
    		byte[] output = new byte[cipherText.length()];
    		byte[] cipher = cipherText.getBytes();
    		for (int i = 0; i < cipherText.length(); i++) 
    		{
                output[i] = (byte)(cipher[i] ^ keyStream[i]);	
            }
    		
    		String out = new String(output);
    		if(out.contains(knowText))
			{
    			result = Base64.getEncoder().encodeToString(output);
			}
    		else		// if the output does not work, go back to the original method with no hint
    		{
    			hint = false;
    		}
    	}
    	
    	// use the rc4 provided by the library with no hint
    	if(!hint)
    	{
			// initialization
			byte key[] = Arrays.copyOf(ARC4Cracker.keyPrefix, 11);
			int a3 = 0;
			while(a3 < 258)
			{		
				int a2 = 0;
				while(a2 < 258)
				{
					int a1 = 0;;
					while(a1 < 258)
					{
						key[8] = (byte)a1;
						key[9] = (byte)a2;
						key[10] = (byte)a3;
			
						// decrypt the RC4 with java class library
						SecretKey secretKey = new SecretKeySpec(key, "ARCFOUR");
				    	Cipher rc4 = Cipher.getInstance("ARCFOUR");
				    	rc4.init(Cipher.DECRYPT_MODE, secretKey);
				        byte[] decryptedText = rc4.doFinal(cipherText.getBytes());
				        String plaintext = new String(decryptedText);
				 
						// check if the plain text consists of the known text
						if(plaintext.contains(knowText))
						{
							result = Base64.getEncoder().encodeToString(plaintext.getBytes());
							break;
						}
						
						a1++;
					}
					a2++;
				}
				a3++;
			}
    	}
    	
    	
		if(result == null)
			return Base64.getEncoder().encodeToString("Not found".getBytes());
    	return result; 
    }
}
