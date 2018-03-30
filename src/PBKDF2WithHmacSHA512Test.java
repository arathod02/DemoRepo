import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class PBKDF2WithHmacSHA512Test {

    public static String PDKDF_ALGORITHM = "PBKDF2WithHmacSHA512" ;
    public static int ITERATION_COUNT = 12288 ;
    public static int SALT_LENGTH = 128 ;
    public static int DERIVED_KEY_LENGTH = 128 ;

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
		
        //Security.insertProviderAt(new BouncyCastleProvider(), 1);

        Provider[] providers = Security.getProviders();
        
        System.out.println("List of Providers available");
        for( Provider provider : providers ){
        	System.out.println(provider.getClass().getSimpleName());
        }
        
        char[] PASSWORD = "123456781234".toCharArray() ;
        
        PBEKeySpec keySpec = new PBEKeySpec(PASSWORD, "salt".getBytes(), ITERATION_COUNT , DERIVED_KEY_LENGTH * 8);
        
        SecretKeyFactory pbkdfKeyFactory = SecretKeyFactory.getInstance(PDKDF_ALGORITHM);
        System.out.println( "\nProvider Used is " + pbkdfKeyFactory.getProvider().getClass().getSimpleName() );
        
        System.out.println( "Hash Signature : " + 
        		Base64.getEncoder().encodeToString( pbkdfKeyFactory.generateSecret(keySpec).getEncoded() ) );
        
	}
}
