using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            long c = ModPow(alpha, k, q);

            long c1 = (m * ModPow(y, k, q)) % q;



            List<long> cipher = new List<long>();

            cipher.Add(c);

            cipher.Add(c1);

            return cipher;

        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            long m = (c2 * ModExp(c1, q - 1 - x, q)) % q;
            return (int)m;

        }
        public long ModExp(long b, long e, long m)
        {
            if (m == 1) return 0;
            long r = 1;
            b = b % m;
            while (e > 0)
            {
                if ((e & 1) == 1) r = (r * b) % m;
                e >>= 1;
                b = (b * b) % m;
            }
            return r;
        }
        public int ModPow(int a1, int a2, int a3)
        {

            int res = 1;

            while (a2 > 0)

            {

                if (a2 % 2 == 1)

                    res = (res * a1) % a3;

                a1 = (a1 * a1) % a3;

                a2 /= 2;
            }


            return res;

        }

    }
}
