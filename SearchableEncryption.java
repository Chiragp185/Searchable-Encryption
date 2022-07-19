import java.util.*;
import java.util.List;
import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.lang.Math;
import java.security.SecureRandom;
import java.util.Random;
import java.util.Map;
import java.util.HashMap;
import java.util.Iterator;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Mac;
import java.math.*;
import javax.crypto.*;
import java.security.spec.KeySpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;
import java.nio.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.awt.*;
import javax.swing.*;
import java.awt.event.*;

class Phase1{
    String[] keys;
    int k=0;
  public String[] keygen()
  {
    int x=8;
    //keygen K = new keygen();
    //Scanner s= new Scanner(System.in);
    //System.out.println("Enter the security parameter (lambda):");
    //x=s.nextInt();
    keys = new String[(int)Math.pow(2,x)];
    possible("",x);
    /*Printing all possible combinations of {0,1}^lambda
    for(int i=0;i<keys.length;i++)
    {
      System.out.println(keys[i]);
    }*/
    SecureRandom rng = new SecureRandom();
    int p=0;
    //Generating prime number using CSPRNG
    do{
      p=rng.nextInt(10^x);
    }while(!isprime(p)&&p!=1);
    System.out.println("Prime Number P:"+p);
    Random random = new Random();
    int choice1,choice2;
    do {
      choice1 = random.nextInt((int)Math.pow(2,x));
      choice2 = random.nextInt((int)Math.pow(2,x));
    } while (choice1==choice2);
    String[] generated_keys = new String[2];
    generated_keys[0] = keys[choice1];
    generated_keys[1] = keys[choice2];
    //System.out.println("Master Key:"+generated_keys[0]);
   //System.out.println("Session Key:"+Session_Key[1]);
    return generated_keys;
  }
  boolean isprime(int num)
  {
    boolean flag = false;
    for (int i = 2; i <= num / 2; ++i) {
      // condition for nonprime number
      if (num % i == 0) {
        flag = true;
        break;
      }
    }
    if (!flag)
      return true;
    else
      return false;
  }
  void possible(String currentString, int lambda)
  {
    if (lambda == 0) {
        keys[k++]=currentString;
        return;
    }
    possible(currentString + "0", lambda - 1);
    possible(currentString + "1", lambda - 1);
  }
}
class Phase2{
  public Object[][] build_index(String Master_Key,byte[] AESkey, String[] Filenames, int nfiles) throws Exception
  {
    Object[][] I = new Object[nfiles+1][100];
    int m=1,size=0;
    I[0][0] = "Index Table";
    for(int f=0;f<nfiles;f++)
    {
    File file = new File(Filenames[f]);
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
    /*System.out.println();
    System.out.println("Words in the Document along with their count:");for( Map.Entry<String,Integer> entry : map.entrySet() ){System.out.println( entry.getKey() + " => " + entry.getValue() );}
    */
    //Hashing
    String[] result = new String[map.size()];
    int k=0;
    HashFunction H = new HashFunction();
    for (Map.Entry<String, Integer> pair : map.entrySet())
    {
      result[k++] = H.hash(pair.getKey(),Master_Key);
    }
    Object[][] A = new Object[2][result.length+1];
    A[0][0] = "Index Table";
   for(int i=0;i<result.length;i++)
    {
      A[0][i+1] = result[i];
    }
    //AES Encryption for Document ID
    AESCBC Ek = new AESCBC();
    String encrypted_docid = Ek.encrypt(Filenames[f],AESkey,"String");
    A[1][0] = encrypted_docid;
    List<String> l = new ArrayList<String>(map.keySet());
    for(int i =1 ; i<2;i++)
    {
      for(int j=1;j<result.length+1;j++)
      {
        double rfvalue = (1.0/map.size())*(1+Math.log(map.get(l.get(j-1))))*Math.log(2);
        A[i][j] = rfvalue*92; //Mask(RF) = Multiply with any random number
      }
    }
    if(f==0)
    {
      size = map.size()+1;
      for(int j=1;j<size;j++)
      {
        I[0][j]=A[0][j];
        I[1][j]=A[1][j];
      }
    }
    else{
    int status=0;
    for(int j=1;j<result.length+1;j++)
    {
      String temp = A[0][j].toString();
      status=0;
      for(int j2=1;j2<size;j2++)
      {
        if((I[0][j2].toString()).equals(temp))
        {
          I[m][j2] = A[1][j];
          status = 1;
          break;
        }
      }
      if(status==0)
      {
        I[0][size] = A[0][j];
        I[m][size] = A[1][j];
        size++;
      }
    }
  }
  I[m][0]=A[1][0];
    m++;
  }
  I[0][0] = size;
  return I;
}
}
class Phase3{
  HashFunction H = new HashFunction();
    AESCBC Ek = new AESCBC();
   public Object[] build_trap(String Master_Key, String Session_Key,byte[] AESkey, String Keyword) throws Exception
   {
     String a = new String();
     a = H.hash(Keyword,Master_Key);
     String b = new String();
     b = Ek.encrypt(Keyword, AESkey,"Hex");
     String c = new String();
     BigInteger ca = new BigInteger(a,16);
     BigInteger cb = new BigInteger(b,16);
     BigInteger cc = ca.multiply(cb);
     c = cc.toString(16);
     String d = new String();
     d = H.hash(b,Session_Key);
     Object[] Twi = new Object[3];
     Twi[0] = d;
     Twi[1] = c;
     int num = 0;
     JFrame jFrame = new JFrame();
     String getMessage = JOptionPane.showInputDialog(jFrame, "Enter the Desired Number of Documents");
     num = Integer.parseInt(getMessage);
     Twi[2] = num;
     return Twi;
   }
}
class Phase4{
    HashFunction H = new HashFunction();
   public String[] search_outcome(Object Twi[], String Session_Key, Object I[][], int size,int nfiles) throws Exception
   {
     boolean found=false;
     String d = Twi[0].toString();
     String c = Twi[1].toString();
     int num = (Integer)Twi[2];
     String[] X = new String[num];
     BigInteger cc = new BigInteger(c,16);//Calculating integer value of c
     for(int i =1;i<size;i++)
     {
       BigInteger a = new BigInteger(I[0][i].toString(),16);//Calculating integer value of a
       BigInteger res = cc.divide(a);// res = c/a
       String result = res.toString(16);// converting the result in string form
       String cainv = H.hash(result,Session_Key);
       if(cainv.equals(d))
       {
        found=true;
        String[] docid = new String[nfiles];
        Double[] rfs = new Double[nfiles];
        int l=0;
        for(int j=1;j<=nfiles;j++)
        {
                docid[l]=I[j][0].toString();
                if(I[j][i] == null) rfs[l] = 0.0;
                else rfs[l] =(Double) I[j][i];
                l++;
        }
        String temp="";
        double tmp=0;
        for(int f=0;f<l;f++)
        {
          for(int j=0;j<l-1-f;j++)
          {
            if(rfs[j]<rfs[j+1])
            {
              tmp=rfs[j];
              temp=docid[j];
              rfs[j]=rfs[j+1];
              docid[j]=docid[j+1];
              rfs[j+1]=tmp;
              docid[j+1]=temp;
            }
          }
        }
        for(int k=0;k<num;k++)
        {
          X[k]=docid[k];
        }
        break;
     }
    }
    if(found==false){
      JFrame frame = new JFrame("");
      JOptionPane.showMessageDialog(frame, "WORD NOT FOUND!","Error", JOptionPane.WARNING_MESSAGE);
      System.exit(0);}
    return X;
   }

}
class Phase5{
  AESCBC Dk = new AESCBC();
  public String[] dec(String[] encrypted,int n,byte[] AESkey) throws Exception
  {
    String[] dec = new String[n];
    for(int i=0;i<n;i++)
    dec[i] = Dk.decrypt(encrypted[i],AESkey);
    return dec;
  }

}
public class SearchableEncryption implements ActionListener{
  JFrame jfrm;
  JButton b1,b2,b3;
  JLabel l1,l2,l3;
  JTextField t1;
  JTextArea area;
  String[] filenames = new String[20];
  int flength=0;
  Phase1 k = new Phase1();
  String Master_Key="", Session_Key="";
  byte[] AESkey;
  Object[][] I;
  int size = 0;
  SearchableEncryption()
  {
    jfrm = new JFrame("Mini Project");
    jfrm.setLayout(null);
    b1 = new JButton("Upload Files");
    b1.addActionListener(this);
    jfrm.add(b1);
    b2 = new JButton("Search Keyword");
    jfrm.add(b2);
    b2.addActionListener(this);
    l1 = new JLabel("<html> <h3> A Novel Ranked Searchable Encryption Scheme based<br> on  Probabilistic Encryption for Cloud Storage Services </h3> </html>");
    jfrm.add(l1);
    l2 = new JLabel(" ");
    jfrm.add(l2);
    l1.setBounds(100,120,450,50);
    b1.setBounds(120,250,140,30);
    b2.setBounds(320,250,140,30);
    l2.setBounds(5,420,180,30);
    jfrm.setSize(600,500);
    jfrm.setVisible(true);
    jfrm.setLocationRelativeTo(null);
    jfrm.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
  }
  public static void main(String args[])
  {
    new SearchableEncryption();
  }
  public void actionPerformed(ActionEvent ae)
  {
    String button = ae.getActionCommand();
    if(button.equals("Upload Files"))
    {
      JFileChooser fc = new JFileChooser();
      fc.setMultiSelectionEnabled(true);
      fc.showOpenDialog(jfrm);
      File[] files = fc.getSelectedFiles();
      for(int i=0;i<files.length;i++)
      {
        filenames[i]=new String(files[i].getPath());
        flength++;
      }
      l2.setText(" ");
      l2.setText(files.length+" files uploaded successfully!");
      //for(int i=0;i<files.length;i++){System.out.println(filenames[i]);}
    }
    if(button.equals("Search Keyword"))
    {
      try{
      jfrm.dispose();
      //new Window2(filenames,flength);
      JFrame jfrm2 = new JFrame("Mini Project");
      jfrm2.setLayout(null);
      JButton b3 = new JButton("Search");
      b3.setBounds(320,30,120,30);
      jfrm2.add(b3);
      b3.addActionListener(this);
      t1 = new JTextField();
      t1.setBounds(100,30,200,30);
      jfrm2.add(t1);
      area = new JTextArea(25,25);
      area.setBounds(30,80,500,250);
      jfrm2.add(area);
      l3 = new JLabel("");
      l3.setBounds(5,420,180,30);
      jfrm2.add(l3);
      jfrm2.setSize(600,500);
      jfrm2.setVisible(true);
      jfrm2.setLocationRelativeTo(null);
      jfrm2.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
      String[] generated_keys = k.keygen();
      Master_Key = generated_keys[0];
      Session_Key = generated_keys[1];
      System.out.println("Master Key:" + Master_Key);
      System.out.println("Session Key:" +Session_Key);
      KeyGenerator kgen = KeyGenerator.getInstance("AES");
      kgen.init(128); // 192 and 256 bits may not be available
      SecureRandom random = new SecureRandom();
      byte[] salt = new byte[16];
      random.nextBytes(salt);
      KeySpec spec = new PBEKeySpec(Master_Key.toCharArray(), salt, 65536, 256); // AES-256
      SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
      AESkey = f.generateSecret(spec).getEncoded();
      //System.out.println(key.toString());
      Phase2 bi = new Phase2();
      I = bi.build_index(Master_Key,AESkey,filenames,flength);
      size = (Integer) I[0][0];
      System.out.println();
      for(int i =0;i<flength+1;i++){for(int j=0;j<size;j++){System.out.printf(I[i][j]+"     ");}System.out.println();System.out.println("------------------------------------------");}
    } catch(Exception e){}
  }
    if(button.equals("Search"))
    {
        try{
          Phase3 bt = new Phase3();
          Object Twi[] = bt.build_trap(Master_Key,Session_Key,AESkey,t1.getText());
          //for(int i =0;i<3 ; i++){System.out.print(Twi[i]+",");}
          Phase4 so = new Phase4();
          String[] X = so.search_outcome(Twi,Session_Key,I,size,flength);
          Phase5 decrypt = new Phase5();
          String[] documentID = decrypt.dec(X,(Integer)Twi[2],AESkey);
          l3.setText("Search Successfull !");
          String temp="\t Documents in Ranked Order:   \n\n";
          for(int i=0;i<(Integer)Twi[2];i++)
          {
              temp+=(i+1)+". "+documentID[i]+"\n";
          }
          Font font = new Font("Verdana", Font.BOLD, 14);
          area.setFont(font);
          area.setText(temp);
        }
        catch(Exception e){}
    }
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
  public String encrypt(String message, byte[] key, String returntype ) throws Exception {
    // Instantiate the cipher
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    byte[] iv = new byte[cipher.getBlockSize()];
    IvParameterSpec ivParams = new IvParameterSpec(iv);
    //System.out.println(Base64.getEncoder().encodeToString(keyaes.getEncoded()));
    SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParams);
    byte[] encrypted = cipher.doFinal((message).getBytes());
    //System.out.println("encrypted string: " + asHex(encrypted));
    //System.out.println("Original string: " +   originalString);
    if(returntype.equals("Hex"))
        return asHex(encrypted);
    else
        return Base64.getEncoder().encodeToString(encrypted);
  }
  public String decrypt(String encrypted, byte[] key) throws Exception
  {
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    byte[] iv = new byte[cipher.getBlockSize()];
    IvParameterSpec ivParams = new IvParameterSpec(iv);
    SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    cipher.init(Cipher.DECRYPT_MODE, keySpec,ivParams);
    byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));
    String originalString = new String(original);
    return originalString;
  }
}
class HashFunction{
    String hmacSHA256Algorithm = "HmacSHA256";
    BytesToHex convert = new BytesToHex();
    String hash(String Message, String Key) throws Exception
    {
      SecretKeySpec secretKeySpec = new SecretKeySpec(Key.getBytes(), hmacSHA256Algorithm);
      Mac mac = Mac.getInstance(hmacSHA256Algorithm);
      mac.init(secretKeySpec);
      String temp = convert.bytesToHex(mac.doFinal(Message.getBytes()));
      return temp;
    }
}
