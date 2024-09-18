using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            Dictionary<int, char> second = new Dictionary<int, char>();
            string Encrypted = "";
            char tmp = 'a';
            for (int i = 0; i < 26; i++)
            {
                if (second.ContainsKey(i))
                {
                    continue;
                }
                else
                {

                    second.Add(i, tmp++);

                }

            }
            plainText = plainText.ToLower();

            for (int i = 0; i < plainText.Length; i++)
            {
                int index = ((plainText[i] - 'a') + key) % 26;
                Encrypted += second[index];

            }
            return Encrypted;

        }

        public string Decrypt(string cipherText, int key)
        {
            Dictionary<int, char> third = new Dictionary<int, char>();
            char c = 'a';
            string dec = "";

            for (int i = 0; i < 26; i++)
            {
                if (third.ContainsKey(i))
                {
                    continue;
                }
                else
                {
                    third.Add(i, c++);
                }

            }
            cipherText = cipherText.ToLower();
            for (int j = 0; j < cipherText.Length; j++)
            {
                int x = (cipherText[j] - 'a') - key;
                if (x < 0)
                {
                    x += 26;
                }
                int index = x % 26;
                dec += third[index];

            }

            return dec;
        }

        public int Analyse(string plainText, string cipherText)
        { 
             int v = 0;
            Dictionary<char, int> s = new Dictionary<char, int>();
            for(char my = 'a'; my <= 'z'; my++)
            {
                if (s.ContainsKey(my))
                {
                    continue;
                }
                else
                {
                    s.Add(my, v++);
                }
            }
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
 
 
            int res = s[plainText[0]] - s[cipherText[0]];
 
 
            
            int res1 = s[plainText[0]];
            int res2 = s[cipherText[0]];

            if (res2 - res1 < 0)
            {
                return (res2 - res1) + 26;
            }
            else
            {
                return (res2 - res1) % 26;
            }
        
        }
    }
}