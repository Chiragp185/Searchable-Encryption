import java.io.*;
import java.util.*;
import java.util.Map;
import java.util.HashMap;
import java.util.Iterator;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Mac;
import java.math.*;
import javax.crypto.*;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import javax.crypto.spec.PBEKeySpec;

class BytesToHex {

  public static String bytesToHex(byte[] bytes) {
    StringBuilder builder = new StringBuilder();
    for (byte b: bytes) {
      builder.append(String.format("%02x", b));
    }
    return builder.toString();
  }
}

class AESCBC{
  public static String asHex (byte buf[])
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

  public static String start(String message) throws Exception {

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
    System.out.println(Base64.getEncoder().encodeToString(keyaes.getEncoded()));
    cipher.init(Cipher.ENCRYPT_MODE, keyaes);
    byte[] encrypted = cipher.doFinal((message).getBytes());
    //System.out.println("encrypted string: " + asHex(encrypted));
    return Base64.getEncoder().encodeToString(encrypted);
  }
}

class build_index
{
  public static void main(String args[]) throws Exception
  {
    File file = new File("doc1.txt");
    //String[] A = new String[];
    BufferedReader br = new BufferedReader(new FileReader(file));
    String st;
    HashMap<String, Integer> map = new HashMap<>();
    while ((st = br.readLine()) != null)
    {
      String[] temp=st.split(" ");
      Integer counter=null;
      for(int i=0;i<temp.length;i++)
      {
          counter=map.get(temp[i]);
          if(map.get(temp[i]) == null)
          {
            map.put(temp[i], 1);
          }
          else
          {
            counter++;
            map.put(temp[i], counter);
          }
      }
    }
    System.out.println();
    System.out.println("Words in the Document along with their count:");
    for( Map.Entry<String,Integer> entry : map.entrySet() )
    {
      System.out.println( entry.getKey() + " => " + entry.getValue() );
    }

    //Hashing
    String[] result = new String[map.size()];
    int k=0;
    String hmacSHA256Algorithm = "HmacSHA256";
    String key = "101"; //Master Key
    BytesToHex convert = new BytesToHex();
    for (Map.Entry<String, Integer> pair : map.entrySet())
    {
      String data = pair.getKey();
      SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), hmacSHA256Algorithm);
      Mac mac = Mac.getInstance(hmacSHA256Algorithm);
      mac.init(secretKeySpec);
      String temp = convert.bytesToHex(mac.doFinal(data.getBytes()));
      result[k++] = temp;
    }
    //Printing HashK(Wi)
    /*
    for(int i=0;i<result.length;i++)
    {
      System.out.println(result[i]);
    }
    */
    System.out.println();
    Object[][] A = new Object[2][result.length+1];
    A[0][0] = "Index Table";
   for(int i=0;i<result.length;i++)
    {
      A[0][i+1] = result[i];
    }
    //AES Encryption for Document ID
    AESCBC Ek = new AESCBC();
    //String encrypted_docid = Ek.start("D1");
    A[1][0] = "GHxVbPVtivXC7Le/5n1hlw==";
    List<String> l = new ArrayList<String>(map.keySet());
    for(int i =1 ; i<2;i++)
    {
      for(int j=1;j<result.length+1;j++)
      {
        double rfvalue = (1.0/map.size())*(1+Math.log(map.get(l.get(j-1))))*Math.log(2);
        A[i][j] = rfvalue*92; //Mask(RF) = Multiply with any random number
      }
    }
    for(int i =0;i<2;i++)
    {
      for(int j=0;j<result.length+1;j++)
      {
        System.out.printf(A[i][j]+"     ");
      }
      System.out.println();
    }
  }
}
