using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public static string alphabet = "abcdefghijklmnopqrstuvwxyz";
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
           
            string n = "";
            string mma = "";
            int e = 0;
            int num = 0;
            while(e< cipherText.Length)
            {
               num = (alphabet.IndexOf(cipherText[e]) - alphabet.IndexOf(plainText[e]));
               num=num+ 26;
               num= num % 26;
               n+= alphabet[num];
               e++;
            }
             mma=mma+ n[0];
            int m = 1;
            int flag = 1;
            do
            {
                if (cipherText == Encrypt(plainText, mma))
                {
                    flag = 0;
                }
                if (flag==0)
                {
                    return mma;
                }
                mma += n[m];
                m++;
            }while(m < n.Length) ;
            return n;
        }

        public string Decrypt(string cipherText, string key)
        {
            string decode = "";
            cipherText = cipherText.ToLower();
            string newkey2 = key;
            for (int i = 0; i < cipherText.Length; i++)
            {
                int k = alphabet.IndexOf(newkey2[i]);
                int c = alphabet.IndexOf(cipherText[i]);
                int totle2 = (c - k) % 26;
                totle2 = (totle2 < 0) ? totle2 + 26 : totle2;
                newkey2 += alphabet[totle2];
                decode += alphabet[totle2];
            }
            return decode;
        }

        public string Encrypt(string plainText, string key)
        {
            string encode = "";
            int c = 0;
            //newkey = newkey.Substring(0, plainText.Length);
            key = key + plainText;
            int total = 0, p = 0, k = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                k = alphabet.IndexOf(key[i]);
                p = alphabet.IndexOf(plainText[i]);
                total = (p + k) % 26;
                encode += alphabet[total];
            }
            return encode;
        }
    }
}
