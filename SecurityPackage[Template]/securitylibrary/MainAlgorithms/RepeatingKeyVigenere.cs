using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public static string alphabet = "abcdefghijklmnopqrstuvwxyz";
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            string n = "";
            string mma = "";
            int e = 0;
            int num = 0;
            while (e < cipherText.Length)
            {
                num = (alphabet.IndexOf(cipherText[e]) - alphabet.IndexOf(plainText[e]));
                num = num + 26;
                num = num % 26;
                n += alphabet[num];
                e++;
            }
            mma = mma + n[0];
            int m = 1;
            int flag = 1;
            do
            {
                if (cipherText.Equals(Encrypt(plainText, mma)))
                {
                    return mma;
                }
                mma += n[m];
                m++;
            } while (m < n.Length);
            return n;
        }
        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            int len = (cipherText.Length / key.Length) + 1;
            for (int i = 0; i < len; i++)
            {
                key += key;
            }
            string decode = "";
            string newkey2 = key;
            for (int i = 0; i < cipherText.Length; i++)
            {
                int k = alphabet.IndexOf(newkey2[i]);
                int c = alphabet.IndexOf(cipherText[i]);
                int totle2 = (c - k) % 26;
                totle2 = (totle2 < 0) ? totle2 + 26 : totle2;
                decode += alphabet[totle2];
            }
            return decode;
        }
        public string Encrypt(string plainText, string key)
        {
            int counter = 0;
            while (true)
            {
                key = key + key[counter];
                counter++;
                if(key.Length == plainText.Length)
                {
                    break;
                }
            }
            string encode = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                int k = alphabet.IndexOf(key[i]);
                int p = alphabet.IndexOf(plainText[i]);
                int total = (p + k) % 26;
                encode += alphabet[total];
            }
            return encode;
        }
    }
}