import java.util.*;
import java.lang.Math;
import java.security.SecureRandom;
import java.util.Random;

class keygen
{
    String[] keys;
    int k=0;
  public static void main(String args[])
  {
    int x=0;
    keygen K = new keygen();
    Scanner s= new Scanner(System.in);
    System.out.println("Enter the security parameter (lambda):");
    x=s.nextInt();
    K.keys = new String[(int)Math.pow(2,x)];
    K.possible("",x);
    //Printing all possible combinations of {0,1}^lambda\
    /*for(int i=0;i<K.keys.length;i++)
    {
      System.out.println(K.keys[i]);
    }*/
    SecureRandom rng = new SecureRandom();
    int p=0;
    //Generating prime number using CSPRNG
    do{
      p=rng.nextInt(10^x);
    }while(!K.isprime(p)&&p!=1);
    System.out.println("Prime Number P:"+p);
    String Master_Key, Session_Key;
    Random random = new Random();
    int choice1,choice2;
    do {
      choice1 = random.nextInt((int)Math.pow(2,x));
      choice2 = random.nextInt((int)Math.pow(2,x));
    } while (choice1==choice2);
    Master_Key = K.keys[choice1];
    Session_Key = K.keys[choice2];
    System.out.println("Master_Key:"+Master_Key);
    System.out.println("Session_Key:"+Session_Key);
  }
  public boolean isprime(int num)
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
  public void possible(String currentString, int lambda)
  {
    if (lambda == 0) {
        keys[k++]=currentString;
        return;
    }
    possible(currentString + "0", lambda - 1);
    possible(currentString + "1", lambda - 1);
  }
}
