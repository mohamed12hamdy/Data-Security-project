using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            List<int> key = new List<int>();
            List<int> FinalLK = key;
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            int temp1 = 0, temp3 = 0;
          for(int temp2 = 0; temp2< cipherText.Length;temp2++)
          {
             if (cipherText[0] == plainText[temp2])
                {
                        int tmm = temp2 + 1;
                do
              {
                  if (cipherText[1] == plainText[tmm])
                        {
                   int m = temp2 + 2;
                   do
                     {
                     if (cipherText[2] == plainText[m])
                      {
                       int lol = temp2 + 3;
                       int c_lol = cipherText.Length;
                       while (lol < c_lol)
                        {
                           if (cipherText[3] == plainText[lol])
                             {
                               if (tmm - temp2 != m - tmm)
                               {
                                 break;
                               }
                            else
                             {
                                temp3 = m - tmm;
                                bool _cond1 = c_lol % temp3 > 0, _cond2 = c_lol % temp3 < 0;
                                if (_cond1 || _cond2)
                                 {
                                      temp1 = c_lol / temp3;
                                      temp1 += 1;
                                 }
                                 else
                                  {
                                    temp1 = c_lol / temp3;
                                    break;
                                 }
                             }
                           }
                             lol += 1;
                                    }
                            }
                            m += 1;
                            }while (m < cipherText.Length) ;
                        }
                        tmm += 1;
                    } while (tmm < cipherText.Length);
                        }
                    }
            char[,] arrayplaintext = new char[temp1, temp3];
            int tmmm = 0, tmmmm2 = 0, tmmm3 = 0;
            while (tmmmm2 < temp1)
            { for (int j = 0; j < temp3; j++)
                { 
                    if (tmmm < plainText.Length)
                    {
                        arrayplaintext[tmmmm2, j] = plainText[tmmm++];
                    }
                }
               tmmmm2++; 
            }
            int m2 = 0;
            while (m2 < temp3)
            {
                int k = 0;
                do
                {
                    if (arrayplaintext[0, m2] == cipherText[k])
                    {
                        if (arrayplaintext[1, m2] == cipherText[k + 1])
                        {
                            if (arrayplaintext[2, m2] == cipherText[k + 2])
                            {
                                tmmm3 = k / temp1;
                                bool InCond1 = k % temp1 > 0, InCond2 = k % temp1 < 0;
                                if (InCond1 || InCond2)
                                {
                                    tmmm3 += 1;
                                }
                                key.Add(tmmm3 + 1);
                                break;
                            }
                        }
                    }
                    k++;
                }while (k < cipherText.Length) ;
                m2 += 1;
            }
            return FinalLK;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            string C_T= cipherText;
            string finaloutput = "";
            C_T = C_T.ToUpper();
            int m = C_T.Length;
            if(m % key.Count != 0)
            {
                m =m + key.Count;
            }
            double colums = m / key.Count;
            int momo = (int)(colums);
            char[,] encription = new char[momo, key.Count];
            int k = 0;
            int tmp = 0;
            int e = 0;
            /*\
           0|1|2|3|4
         0|1|3|4|2|5
         1|c|o|m|p|u
         2|t|e|r|s|c
         3|i|e|n|c|e
            encribtion[0,0],[0,1].[0,2].[0,3]="cti"
            encribtion[3,0].[3.1].[3,2].[3,3]="psc"
            encribtion[1,0].[1.1].[1,2].[1,3]="oee"
            encribtion[2,0].[2.1].[2,2].[2,3]="mrn"
            encribtion[4,0].[4.1].[4,2].[4,3]="uce"
            ecription [0,0]+[0,1]+[0,2]+[0+3]+[0,4]="compu"
            ecription [1,0]+[1,1]+[1,2]+[1,3]+[1,4]="tersc"
            ecription [2,0]+[2,1]+[2,2]+[2+3]+[2,4]="ience"
            finall===computerscience
            */
            do
            {
                k = key.IndexOf(e + 1);
                int j = 0;
                do 
                {
                    if (tmp < C_T.Length)
                    {
                        encription[j, k] = C_T[tmp];
                        tmp++;
                    }
                    j++;
                }while (j < colums);
                e++;
            }while (e < key.Count);
            int f = 0;
            do
            {
                int j = 0;
                do 
                {
                    finaloutput = finaloutput + encription[f, j];
                    j++;
                }while(j < key.Count) ;
                f++;
            }while (f< colums) ;


            return finaloutput.ToUpper();
        }

        public string Encrypt(string plainText, List<int> key)
        {   /*encryption in columnar
             P.T : Computer Science
             Key = 1 3 4 2 5
            first we make a table with number of colums and number of row
            number of colums= length of key
            number of row is the totl of plantext divided keylength
            1|3|4|2|5
            c|o|m|p|u
            t|e|r|s|c
            i|e|n|c|e
            we output the colum of smallestnumber and smallest
            C.T = CTIPSCOEEMRNUCE

           if the matrix we have a empty place matrix add x in this place
            */
            string p_t = plainText;
            int columns = key.Count;
            int pt_length = plainText.Length;
            double numberofrows = plainText.Length / columns;
            int rows = (int)Math.Ceiling((double)p_t.Length / columns);
            int size= rows * columns;
            string allstring = "";
            int temp1 = 0, temp2 = 0;
            string[] table = new string[30];
            for(int indx = 0;indx < 30;indx++)
            {
                table[indx] = "";
            }
            for(int temp3=0;temp3 < columns;temp3++)
            {
                temp1= temp3;
                int indx3 = temp1;
                for(; indx3 < pt_length; indx3++)
                {
                    if (temp1 < pt_length)
                    {
                        table[key[temp2] - 1] = table[key[temp2] - 1] + plainText[temp1];
                        temp1 = temp1 + columns;
                    }
                }
                temp2 = temp2 + 1;
            }
            /*
             arr[0]="cti"
             arr[1]="psc"
             arr[2]="oee"
             arr[3]="mrn"
             arr[4]="uce"
            encription===>arr[0]+..............+arr[4]==>ctipscoeemrnuce
             */

            for (int i = 0; i < columns; i++)
            {
                allstring = allstring + table[i];
            }
            return allstring;
        }
    }
}
