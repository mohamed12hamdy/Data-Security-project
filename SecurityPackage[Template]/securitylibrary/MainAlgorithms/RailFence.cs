using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            for (int i = 0; i < plainText.Length; i++)
            {
                string res = Encrypt(plainText, i + 1);
                if (res == cipherText)
                {
                    return i + 1;

                }
            }
            return -1;
        }

        public string Decrypt(string cipherText, int key)
        {
            int sizee = Convert.ToInt32(Math.Ceiling(cipherText.Length / (double)key));
            char[,] arr = new char[sizee, key];
            int b = 0;
            for (int j = 0; j < key; j++)
            {
                for (int i = 0; i < sizee; i++)
                {
                    if (b < cipherText.Length)
                    {
                        arr[i, j] = cipherText[b++];
                    }
                }
            }
            string dec = string.Empty;
            for (int i = 0; i < sizee; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    if (arr[i, j] != '\0')
                        dec += arr[i, j];
                }
            }





            return dec;

        }
        public string Encrypt(string plainText, int key)
        {
            string Cout = "";
            int c = 0;
            string mo = plainText;
            String.Join(mo, mo.Split(' '));
            List<List<char>> list = new List<List<char>>();
            double n = plainText.Length / key;
            int each = (int)Math.Ceiling((double)mo.Length / key);
            int e = 0;
            int m = 0;
            int i = 0;
            while (e < key)
            {
                list.Add(new List<char>());
                e++;
            }
           while(m < each)
            {
                int j = 0;
                while (j < key && j < mo.Length)
                {
                    list[j].Add(mo[c]);
                    c++;
                    if (c == mo.Length)
                    {
                        break;
                    }
                    j++;
                }
                m++;
            }
            while (i < list.Count)
            {
                int j = 0;
                while (j < list[i].Count)
                {
                    Cout += list[i][j];
                    j++;
                }
                i++;
            }
            string outt= Cout.ToUpper();
            return outt;
        }
    }  
}
