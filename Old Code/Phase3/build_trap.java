import java.io.*;
import java.util.*;
import java.util.Map;
import java.util.HashMap;
import java.util.Iterator;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Mac;
import java.nio.*;
import java.math.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.spec.KeySpec;
import javax.crypto.spec.PBEKeySpec;

class AESCBC{
  String Ciphertxt;
  public String asHex (byte buf[])
  {

   StringBuffer strbuf = new StringBuffer(buf.length * 2);
   int i;

   for (i = 0; i < buf.length; i++) {
    if (((int) buf[i] & 0xff) < 0x10)
     strbuf.append("0");

    strbuf.append(Long.toString((int) buf[i] & 0xff, 16));
   }

   return strbuf.toString();
  }

  public String start(String message) throws Exception {

    // Get the KeyGenerator
    KeyGenerator kgen = KeyGenerator.getInstance("AES");
    kgen.init(128); // 192 and 256 bits may not be available
    SecureRandom random = new SecureRandom();
    byte[] salt = new byte[16];
    random.nextBytes(salt);
    KeySpec spec = new PBEKeySpec("101".toCharArray(), salt, 65536, 256); // AES-256
    SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
    byte[] key = f.generateSecret(spec).getEncoded();
    SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    SecretKey keyaes = keySpec;
    // Instantiate the cipher
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, keyaes);
    byte[] encrypted = cipher.doFinal((message).getBytes());
    Ciphertxt = Base64.getEncoder().encodeToString(encrypted);
    return asHex(encrypted);
    //return Base64.getEncoder().encodeToString(encrypted);
  }
}

class BytesToHex {

  public static String bytesToHex(byte[] bytes) {
    StringBuilder builder = new StringBuilder();
    for (byte b: bytes) {
      builder.append(String.format("%02x", b));
    }
    return builder.toString();
  }

}

class build_trap{
  public static void main(String args[]) throws Exception
  {
    HashMap<String,Integer> map = new HashMap<>();
  //  map.put("study",1);
  //  map.put("SASTRA",1);
  //  map.put("this",2);
  //  map.put("is",2);
      map.put("Chirag",1);
  //  map.put("K",1);
  //  map.put("Anand",1);
  //  map.put("We",1);
  //  map.put("at",1);
  //  map.put("Hello",2);
  //  map.put("University",1);
  //  map.put("Parikh",1);
  //  map.put("Raj",1);
    //System.out.println(map);
    String a = new String();
    String hmacSHA256Algorithm = "HmacSHA256";
    String key = "101"; //Master Key
    String SessionKey = "110"; // Session Key
    BytesToHex convert = new BytesToHex();
    for (Map.Entry<String, Integer> pair : map.entrySet())
    {
      String data = pair.getKey();
      SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), hmacSHA256Algorithm);
      Mac mac = Mac.getInstance(hmacSHA256Algorithm);
      mac.init(secretKeySpec);
      a = convert.bytesToHex(mac.doFinal(data.getBytes()));
    }
    System.out.println("A = "+a);
    String b = new String();
    AESCBC Ek = new AESCBC();
    for (Map.Entry<String, Integer> pair : map.entrySet())
    {
      String data = pair.getKey();
      String encrypted_ = Ek.start(data);
      b = encrypted_;
    }
    System.out.println("B = "+b);
    String c = new String();
    BigInteger ca = new BigInteger(a,16);
    BigInteger cb = new BigInteger(b,16);
    BigInteger cc = ca.multiply(cb);
    c = cc.toString(16);
    System.out.println("C(Hex) = "+c);
    System.out.println("C(CipherText) = "+Ek.Ciphertxt);
    String d = new String();
    for (Map.Entry<String, Integer> pair : map.entrySet())
    {
      String data = b;
      SecretKeySpec secretKeySpec = new SecretKeySpec(SessionKey.getBytes(), hmacSHA256Algorithm);
      Mac mac = Mac.getInstance(hmacSHA256Algorithm);
      mac.init(secretKeySpec);
      d = convert.bytesToHex(mac.doFinal(data.getBytes()));
    }
    System.out.println("D = "+ d);
    Object[] Twi = new Object[3];
    Twi[0] = d;
    Twi[1] = c;
    int num = 0;
    Scanner s= new Scanner(System.in);
    System.out.println("Enter the Desired Number of Documents:");
    num=s.nextInt();
    Twi[2] = num;
    System.out.println("-------------------------------------------TRAPDOOR:-------------------------------------------------");
    System.out.print("(");
    for(int i =0;i<3 ; i++)
    {
      System.out.print(Twi[i]+",");
    }
    System.out.print(")");
  }
}
