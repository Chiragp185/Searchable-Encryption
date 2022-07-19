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
class BytesToHex {

  public static String bytesToHex(byte[] bytes) {
    StringBuilder builder = new StringBuilder();
    for (byte b: bytes) {
      builder.append(String.format("%02x", b));
    }
    return builder.toString();
  }
}
class search_outcome
{
    public static void main(String args[]) throws Exception
    {
      Object[][] I = {{"Index Table","d2b92696b7cbadf26a0d7a1c8f1e572151f6a3b2c8d82a284fc2256f3ccd7c7f","1fba41cb9883134baddd23f58b46af6ffc6e843550f88d104c216d52a080d42a",
                          "01de5a9ff10c84ac3d4eace9ff6ef462a67a2a79cacb4979874f76bbac30a550",
                          "a2e9c59ad23fb8ba0135a49cfe23ef1b3db5d1ee8383ec986887b0b6a71734f4",
                          "6296e278c040475fd7669efd51182c7a42d83d3096df89917e5ff5fe35d0d642","cb0ab05c825c763134cc0b0247f49f2c54a9b9f9ee04fb0e756ee9a204e001a8",
                          "2aedde07bd3d089327593565b58bb399fe3a8282950b6d8d55612116cebd9ba4",
                          "79bceb923d98f13642ce9f740609f50ef4067e948cb0182770a7a0d1663dd659","8fcdf8e6a47662f056f4f3511c06a8cc4682d06de6caac34122aea263610beee",
                          "d6e399c807175d8d024fb509e0f5dd0d18c114f4fbad2c9a2ec1023b14995273",
                          "fc0f840182fcd1c178f6338b68355494aca28f09cf7a11f2ea2afc0fedf980f7","7b906cd29f43cf487a132697718342b19f0128682e84bafa02fc777323e2bc7f",
                          "1b494ab2d2b71a37008efc0d995a87d4937e7a7e00c47c3d135eb6c9a7b229b4"
                        },
                      {
                        "GHxVbPVtivXC7Le/5n1hlw==",4.905349277808844,4.905349277808844,8.305478299383807,8.305478299383807,4.905349277808844,4.905349277808844,
                        4.905349277808844,4.905349277808844,4.905349277808844,8.305478299383807,4.905349277808844,4.905349277808844,4.905349277808844
                      }
                    };
     Object[] Twi = {"a49008e675ceb4e523a4957fe2483fddbf1fd186283acea46f55be38f804101a",
                      "1206f3a0f2bafd66a5cc3d521614299395ae35bfbdb4e9b48e0dc1caede0a12e0f1b3f77b3d9f1f47060feb6e27611e6"
                      ,1};
     String SessionKey = "110";
     String X = new String();
     String d = Twi[0].toString();
     String c = Twi[1].toString();
     int num = (Integer)Twi[2];
     //String a = new String();
     for(int i =1;i<14;i++)
     {
          BigInteger a = new BigInteger(I[0][i].toString(),16);
          //System.out.println(ainv);
          BigInteger cc = new BigInteger(c,16);
          BigInteger res = cc.divide(a);
          String result = res.toString(16);
          //System.out.println(result);
          String cainv = new String();
          String hmacSHA256Algorithm = "HmacSHA256";
          BytesToHex convert = new BytesToHex();
          String data = result;
          SecretKeySpec secretKeySpec = new SecretKeySpec(SessionKey.getBytes(), hmacSHA256Algorithm);
          Mac mac = Mac.getInstance(hmacSHA256Algorithm);
          mac.init(secretKeySpec);
          cainv = convert.bytesToHex(mac.doFinal(data.getBytes()));
          //System.out.println(cainv);
          if(cainv.equals(d))
          {
             double max;
             max = (double)I[1][i];
             X = I[1][0].toString();
             for(int j = 1 ; j<=num ; j++)
             {
                  if((double)I[j][i]>=max)
                  {
                    max = (double)I[1][j];
                    X = I[j][0].toString();
                  }
             }
             System.out.println("Max RF Value:" + max);
             System.out.println("Document ID(Encrypted):"+ X);
             break;
          }
     }
  }
}
