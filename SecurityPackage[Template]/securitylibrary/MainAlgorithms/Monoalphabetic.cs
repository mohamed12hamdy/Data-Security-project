using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            SortedDictionary<char, char> equivalent = new SortedDictionary<char, char>();
            string doneChar = null;
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            
            for (int i = 0; i < plainText.Length; i++)
            {
                if (!equivalent.ContainsKey(plainText[i]))
                {
                    equivalent.Add(plainText[i], cipherText[i]);
                    doneChar += cipherText[i];
                }
            }
            string key = null;
            for (char i = 'a'; i <= 'z'; i++)
            {
                if (!equivalent.ContainsKey(i))
                {
                    for (char j = 'a'; j <= 'z'; j++)
                    {
                        if (!doneChar.Contains(j))
                        {
                            equivalent.Add(i, j);
                            doneChar += j;
                            break;
                        }
                    }
                }

            }
            foreach (var i in equivalent)
                key += i.Value;

            return key;

           
        }

        public string Decrypt(string cipherText, string key)
        {
            Dictionary<char, char> equivalent = new Dictionary<char, char>();
            int j = 0;
            cipherText = cipherText.ToLower();
            for (char i = 'A'; i <= 'Z'; i++)
            {
                equivalent.Add(key[j], i);
                j++;
            }
            string plainText = null;
            for (int i = 0; i < cipherText.Length; i++)
            {
                plainText += equivalent[cipherText[i]];
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            Dictionary<char, char> equivalent = new Dictionary<char, char>();

            int j = 0;
            plainText = plainText.ToLower();
            for (char i = 'a'; i <= 'z'; i++)
            {
                equivalent.Add(i, key[j]);
                j++;
            }
            string cipherText = null;
            for (int i = 0; i < plainText.Length; i++)
            {
                cipherText += equivalent[plainText[i]];
            }
            return cipherText;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            string charctersFreq = "ETAOINSRHLDCUMFPGWYBVKXJQZ".ToLower();
            Dictionary<char, char> equivalent = new Dictionary<char, char>();
            Dictionary<char, int> freq = new Dictionary<char, int>();


            cipher = cipher.ToLower();
            //kol 7rf w odamo al frequency bt3to mn al mwgoden f cipher
            foreach (char i in cipher)
            {
                if (freq.ContainsKey(i))
                    freq[i]++;
                else
                    freq.Add(i, 0);
            }

            //trteb al 7rof al gwa [freq] mn al kber l al so8yr
            var sortedfreq = from entry in freq orderby entry.Value descending select entry;
            int count = 0;
            foreach (var i in sortedfreq)
            {
                equivalent.Add(i.Key, charctersFreq[count]);
                count++;
            }


            string key = "";
            foreach (char i in cipher)
            {
                key += equivalent[i];
            }
            return key;

            //throw new NotImplementedException();
        }
    }
}