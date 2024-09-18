using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            int[,] pc1 = new int[8, 7] { { 57, 49, 41, 33, 25, 17, 9 }, { 1, 58, 50, 42, 34, 26, 18 }, { 10, 2, 59, 51, 43, 35, 27 }, { 19, 11, 3, 60, 52, 44, 36 }, { 63, 55, 47, 39, 31, 23, 15 }, { 7, 62, 54, 46, 38, 30, 22 }, { 14, 6, 61, 53, 45, 37, 29 }, { 21, 13, 5, 28, 20, 12, 4 } };

            int[,] pc2 = new int[8, 6] { { 14, 17, 11, 24, 1, 5 }, { 3, 28, 15, 6, 21, 10 }, { 23, 19, 12, 4, 26, 8 }, { 16, 7, 27, 20, 13, 2 }, { 41, 52, 31, 37, 47, 55 }, { 30, 40, 51, 45, 33, 48 }, { 44, 49, 39, 56, 34, 53 }, { 46, 42, 50, 36, 29, 32 } };

            int[,] m1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
            int[,] m2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
            int[,] m3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
            int[,] m4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
            int[,] m5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
            int[,] m6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
            int[,] m7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
            int[,] m8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

            int[,] P = new int[8, 4] { { 16, 7, 20, 21 }, { 29, 12, 28, 17 }, { 1, 15, 23, 26 }, { 5, 18, 31, 10 }, { 2, 8, 24, 14 }, { 32, 27, 3, 9 }, { 19, 13, 30, 6 }, { 22, 11, 4, 25 } };

            int[,] EB = new int[8, 6] { { 32, 1, 2, 3, 4, 5 }, { 4, 5, 6, 7, 8, 9 }, { 8, 9, 10, 11, 12, 13 }, { 12, 13, 14, 15, 16, 17 }, { 16, 17, 18, 19, 20, 21 }, { 20, 21, 22, 23, 24, 25 }, { 24, 25, 26, 27, 28, 29 }, { 28, 29, 30, 31, 32, 1 } };

            int[,] IP = new int[8, 8] { { 58, 50, 42, 34, 26, 18, 10, 2 }, { 60, 52, 44, 36, 28, 20, 12, 4 }, { 62, 54, 46, 38, 30, 22, 14, 6 }, { 64, 56, 48, 40, 32, 24, 16, 8 }, { 57, 49, 41, 33, 25, 17, 9, 1 }, { 59, 51, 43, 35, 27, 19, 11, 3 }, { 61, 53, 45, 37, 29, 21, 13, 5 }, { 63, 55, 47, 39, 31, 23, 15, 7 } };

            int[,] IP_1 = new int[8, 8] { { 40, 8, 48, 16, 56, 24, 64, 32 }, { 39, 7, 47, 15, 55, 23, 63, 31 }, { 38, 6, 46, 14, 54, 22, 62, 30 }, { 37, 5, 45, 13, 53, 21, 61, 29 }, { 36, 4, 44, 12, 52, 20, 60, 28 }, { 35, 3, 43, 11, 51, 19, 59, 27 }, { 34, 2, 42, 10, 50, 18, 58, 26 }, { 33, 1, 41, 9, 49, 17, 57, 25 } };


            string bcipher = Convert.ToString(Convert.ToInt64(cipherText, 16), 2).PadLeft(64, '0');
            string bkey = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');

            string L1= "";
            string R1 = "";
            int n = 0;
            while (n < bcipher.Length / 2)
            {
                L1 = L1+ bcipher[n];
                R1 = R1 + bcipher[n+ bcipher.Length / 2];
                n++;
            }

            
            string temp1 = "";
            List<string> Cc = new List<string>();
            List<string> Dd = new List<string>();
            int o = 0;
            while (o < 8)
            {
                for (int j = 0; j < 7; j++)
                {
                    temp1 = temp1 + bkey[pc1[o, j] - 1];
                }
                o++;
            }

            string co = temp1.Substring(0, 28);
            string dd= temp1.Substring(28, 28);

            string temp = "";
            int mo = 0;
            while(mo <= 16)
            {
                Cc.Add(co);
                Dd.Add(dd);
                temp = "";
                if (mo == 0 || mo == 1 ||  mo == 8 ||  mo == 15)
                {
                    temp = temp + co[0];
                    co = co.Remove(0, 1);
                    co = co + temp;
                    temp = "";
                    temp = temp + dd[0];
                    dd = dd.Remove(0, 1);
                    dd = dd + temp;
                }
                else
                {
                    temp = temp + co.Substring(0, 2);
                    co = co.Remove(0, 2);
                    co = co + temp;
                    temp = "";
                    temp = temp + dd.Substring(0, 2);
                    dd = dd.Remove(0, 2);
                    dd = dd + temp;
                }
                mo++;
            }

            List<string> keys = new List<string>();
            int n1 = 0;
            while(n1 < Dd.Count)
            {
                keys.Add(Cc[n1] + Dd[n1]);
                n1++;
            }

            //k1 --> k16 by pc-2
            List<string> nkeys = new List<string>();
            int n2 = 1;
            while( n2 < keys.Count)
            {
                temp1 = "";
                temp = "";
                temp = keys[n2];
                int i = 0;
                while(i < 8)
                {
                    int j = 0;
                    while( j < 6)
                    {
                        temp1 = temp1 + temp[pc2[i, j] - 1];
                        j++;
                    }
                    i++;
                }

                nkeys.Add(temp1);
                n2++;
            }

            //premutation by IP for plain text
            string imo = "";
            int momo = 0;
            while(momo < 8)
            {
                for (int j = 0; j < 8; j++)
                {
                    imo = imo + bcipher[IP[momo, j] - 1];
                }
                momo++;
            }

            List<string> L = new List<string>();
            List<string> R = new List<string>();

            string l = imo.Substring(0, 32);
            string r = imo.Substring(32, 32);

            L.Add(l);
            R.Add(r);
            string x = "";
            string h = "";

            string ebit = "";
            string exork = "";
            List<string> sbox = new List<string>();
            //string sb = "";
            string t = "";
            int row = 0;
            int col = 0;
            string tsb = "";
            string pp = "";
            string lf = "";
            int bb=0;
            while(bb < 16)
            {
                L.Add(r);
                exork = "";
                ebit = "";
                lf = "";
                pp = "";
                sbox.Clear();
                tsb = "";
                col = 0;
                row = 0;
                t = "";
                int mmmm = 0;
                while(mmmm < 8)
                {
                    int mmmm2 = 0;
                    while (mmmm2<6)
                    {
                        ebit = ebit + r[EB[mmmm, mmmm2] - 1];
                        mmmm2++;
                    }
                    mmmm++;
                }
                int g = 0;
                while (g < ebit.Length)
                {
                    exork = exork + (nkeys[nkeys.Count - 1 - bb][g] ^ ebit[g]).ToString();
                    g++;
                }
                int zezo=0;
                while(zezo < exork.Length)
                {
                    t = "";
                    for (int y = zezo; y < 6 + zezo; y++)
                    {
                        if (6 + zezo <= exork.Length)
                            t = t + exork[y];
                    }
                    zezo = zezo + 6;

                    sbox.Add(t);
                }

                t = "";
                int sb = 0;
                int soso = 0;
                while(soso < sbox.Count)
                {
                    t = sbox[soso];
                    x = t[0].ToString() + t[5];
                    h = t[1].ToString() + t[2] + t[3] + t[4];

                    row = Convert.ToInt32(x, 2);
                    col = Convert.ToInt32(h, 2);
                    if (soso == 0)
                    {
                        sb = m1[row, col];
                    }
                    if (soso == 1)
                    {
                        sb = m2[row, col];
                    }
                    if (soso == 2)
                    {
                        sb = m3[row, col];
                    }
                    if (soso == 3)
                    {
                        sb= m4[row, col];
                    }
                    if (soso == 4)
                    {
                        sb = m5[row, col];
                    }
                    if (soso == 5)
                    { 
                        sb = m6[row, col];
                    }
                   

                    if (soso == 6)
                    {
                        sb = m7[row, col];
                    }
                    if (soso == 7)
                    {
                        sb = m8[row, col];
                    }
                    tsb = tsb + Convert.ToString(sb, 2).PadLeft(4, '0');
                    soso++;
                }

                x = "";
                h = "";
                int kk = 0;
                while(kk < 8)
                {
                    int j = 0;
                    while(j < 4)
                    {
                        pp = pp + tsb[P[kk, j] - 1];
                        j++;
                    }
                    kk++;
                }
                int ko = 0;
                while(ko< pp.Length)
                {
                    lf = lf + (pp[ko] ^ l[ko]).ToString();
                    ko++;
                }
                r = lf;
                l = L[bb + 1];
                R.Add(r);
                bb++;
            }

            string nono = R[16] + L[16];
            string ciphertxt = "";
            int mmm = 0;
            while(mmm< 8)
            {
                for (int j = 0; j < 8; j++)
                {
                    ciphertxt = ciphertxt + nono[IP_1[mmm, j] - 1];
                }
                mmm++;
            }
            string pm = "0x" + Convert.ToInt64(ciphertxt, 2).ToString("X").PadLeft(16, '0');
            return pm;
        }

        public override string Encrypt(string plainText, string key)
        {
            int[,] pc1 = new int[8, 7] { { 57, 49, 41, 33, 25, 17, 9 }, { 1, 58, 50, 42, 34, 26, 18 }, { 10, 2, 59, 51, 43, 35, 27 }, { 19, 11, 3, 60, 52, 44, 36 }, { 63, 55, 47, 39, 31, 23, 15 }, { 7, 62, 54, 46, 38, 30, 22 }, { 14, 6, 61, 53, 45, 37, 29 }, { 21, 13, 5, 28, 20, 12, 4 } };

            int[,] pc2 = new int[8, 6] { { 14, 17, 11, 24, 1, 5 }, { 3, 28, 15, 6, 21, 10 }, { 23, 19, 12, 4, 26, 8 }, { 16, 7, 27, 20, 13, 2 }, { 41, 52, 31, 37, 47, 55 }, { 30, 40, 51, 45, 33, 48 }, { 44, 49, 39, 56, 34, 53 }, { 46, 42, 50, 36, 29, 32 } };

            int[,] m1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
            int[,] m2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
            int[,] m3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
            int[,] m4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
            int[,] m5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
            int[,] m6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
            int[,] m7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
            int[,] m8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

            int[,] P = new int[8, 4] { { 16, 7, 20, 21 }, { 29, 12, 28, 17 }, { 1, 15, 23, 26 }, { 5, 18, 31, 10 }, { 2, 8, 24, 14 }, { 32, 27, 3, 9 }, { 19, 13, 30, 6 }, { 22, 11, 4, 25 } };
            int[,] EB = new int[8, 6] { { 32, 1, 2, 3, 4, 5 }, { 4, 5, 6, 7, 8, 9 }, { 8, 9, 10, 11, 12, 13 }, { 12, 13, 14, 15, 16, 17 }, { 16, 17, 18, 19, 20, 21 }, { 20, 21, 22, 23, 24, 25 }, { 24, 25, 26, 27, 28, 29 }, { 28, 29, 30, 31, 32, 1 } };


            int[,] IP = new int[8, 8] { { 58, 50, 42, 34, 26, 18, 10, 2 }, { 60, 52, 44, 36, 28, 20, 12, 4 }, { 62, 54, 46, 38, 30, 22, 14, 6 }, { 64, 56, 48, 40, 32, 24, 16, 8 }, { 57, 49, 41, 33, 25, 17, 9, 1 }, { 59, 51, 43, 35, 27, 19, 11, 3 }, { 61, 53, 45, 37, 29, 21, 13, 5 }, { 63, 55, 47, 39, 31, 23, 15, 7 } };

            int[,] IP_1 = new int[8, 8] { { 40, 8, 48, 16, 56, 24, 64, 32 }, { 39, 7, 47, 15, 55, 23, 63, 31 }, { 38, 6, 46, 14, 54, 22, 62, 30 }, { 37, 5, 45, 13, 53, 21, 61, 29 }, { 36, 4, 44, 12, 52, 20, 60, 28 }, { 35, 3, 43, 11, 51, 19, 59, 27 }, { 34, 2, 42, 10, 50, 18, 58, 26 }, { 33, 1, 41, 9, 49, 17, 57, 25 } };


            string bplain = Convert.ToString(Convert.ToInt64(plainText, 16), 2).PadLeft(64, '0');
            string bkey = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');

            string L1 = "";
            string R1 = "";
            int n = 0;
            while (n < bplain.Length / 2)
            {
                L1 = L1 + bplain[n];
                R1 = R1 + bplain[n + bplain.Length / 2];
                n++;
            }

            string temp1 = "";
            List<string> Cc = new List<string>();
            List<string> Dd = new List<string>();
            int o = 0;
            while (o < 8)
            {
                for (int j = 0; j < 7; j++)
                {
                    temp1 = temp1 + bkey[pc1[o, j] - 1];
                }
                o++;
            }

            //C and D
            string co = temp1.Substring(0, 28);
            string dd = temp1.Substring(28, 28);

            string temp = "";
            int mo = 0;
            while (mo <= 16)
            {
                Cc.Add(co);
                Dd.Add(dd);
                temp = "";
                if (mo == 0 || mo == 1 || mo == 8 || mo == 15)
                {
                    temp = temp + co[0];
                    co = co.Remove(0, 1);
                    co = co + temp;
                    temp = "";
                    temp = temp + dd[0];
                    dd = dd.Remove(0, 1);
                    dd = dd + temp;
                }
                else
                {
                    temp = temp + co.Substring(0, 2);
                    co = co.Remove(0, 2);
                    co = co + temp;
                    temp = "";
                    temp = temp + dd.Substring(0, 2);
                    dd = dd.Remove(0, 2);
                    dd = dd + temp;
                }
                mo++;
            }

            List<string> keys = new List<string>();
            int n1 = 0;
            while (n1 < Dd.Count)
            {
                keys.Add(Cc[n1] + Dd[n1]);
                n1++;
            }

            //k1 --> k16 by pc-2
            List<string> nkeys = new List<string>();
            int n2 = 1;
            while (n2 < keys.Count)
            {
                temp1 = "";
                temp = "";
                temp = keys[n2];
                int i = 0;
                while (i < 8)
                {
                    int j = 0;
                    while (j < 6)
                    {
                        temp1 = temp1 + temp[pc2[i, j] - 1];
                        j++;
                    }
                    i++;
                }

                nkeys.Add(temp1);
                n2++;
            }


            //premutation by IP for plain text
            string imo = "";
            int momo = 0;
            while (momo < 8)
            {
                for (int j = 0; j < 8; j++)
                {
                    imo = imo + bplain[IP[momo, j] - 1];
                }
                momo++;
            }


            List<string> L = new List<string>();
            List<string> R = new List<string>();

            string l = imo.Substring(0, 32);
            string r = imo.Substring(32, 32);

            L.Add(l);
            R.Add(r);
            string x = "";
            string h = "";

            string ebit = "";
            string exork = "";
            List<string> sbox = new List<string>();
            //string sb = "";
            string t = "";
            int row = 0;
            int col = 0;
            string tsb = "";
            string pp = "";
            string lf = "";
            int bb = 0;
            while(bb< 16)
            {
                L.Add(r);
                exork = "";
                ebit = "";
                lf = "";
                pp = "";
                sbox.Clear();
                tsb = "";
                col = 0;
                row = 0;
                t = "";
                int mmmm = 0;
                while (mmmm < 8)
                {
                    int mmmm2 = 0;
                    while (mmmm2 < 6)
                    {
                        ebit = ebit + r[EB[mmmm, mmmm2] - 1];
                        mmmm2++;
                    }
                    mmmm++;
                }
                int g = 0;
                while (g < ebit.Length)
                {
                    exork = exork + (nkeys[bb][g] ^ ebit[g]).ToString();
                    g++;
                }
                int zezo = 0;
                while (zezo < exork.Length)
                {
                    t = "";
                    for (int y = zezo; y < 6 + zezo; y++)
                    {
                        if (6 + zezo <= exork.Length)
                            t = t + exork[y];
                    }
                    zezo = zezo + 6;

                    sbox.Add(t);
                }

                t = "";
                int sb = 0;
                int soso = 0;
                while (soso < sbox.Count)
                {
                    t = sbox[soso];
                    x = t[0].ToString() + t[5];
                    h = t[1].ToString() + t[2] + t[3] + t[4];

                    row = Convert.ToInt32(x, 2);
                    col = Convert.ToInt32(h, 2);
                    if (soso == 0)
                    {
                        sb = m1[row, col];
                    }
                    if (soso == 1)
                    {
                        sb = m2[row, col];
                    }
                    if (soso == 2)
                    {
                        sb = m3[row, col];
                    }
                    if (soso == 3)
                    {
                        sb = m4[row, col];
                    }
                    if (soso == 4)
                    {
                        sb = m5[row, col];
                    }
                    if (soso == 5)
                    {
                        sb = m6[row, col];
                    }


                    if (soso == 6)
                    {
                        sb = m7[row, col];
                    }
                    if (soso == 7)
                    {
                        sb = m8[row, col];
                    }
                    tsb = tsb + Convert.ToString(sb, 2).PadLeft(4, '0');
                    soso++;
                }
                x = "";
                h = "";

                int kk = 0;
                while (kk < 8)
                {
                    int j = 0;
                    while (j < 4)
                    {
                        pp = pp + tsb[P[kk, j] - 1];
                        j++;
                    }
                    kk++;
                }
                int ko = 0;
                while (ko < pp.Length)
                {
                    lf = lf + (pp[ko] ^ l[ko]).ToString();
                    ko++;
                }

                r = lf;
                l = L[bb + 1];
                R.Add(r);
                bb++;
            }


            string nono = R[16] + L[16];
            string ciphertxt = "";
            int mmm = 0;
            while (mmm < 8)
            {
                for (int j = 0; j < 8; j++)
                {
                    ciphertxt = ciphertxt + nono[IP_1[mmm, j] - 1];
                }
                mmm++;
            }
            string ct = "0x" + Convert.ToInt64(ciphertxt, 2).ToString("X");
            return ct;
        }
    }
}