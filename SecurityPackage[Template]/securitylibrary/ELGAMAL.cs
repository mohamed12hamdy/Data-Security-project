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
            List<long> cipher = new List<long>();
            long mo = ModPower(alpha, k, q);
            long mo2 = (m * ModPower(y, k, q)) % q;
            cipher.Add(mo);
            cipher.Add(mo2);
            return cipher;

        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            long m0 = (c2 * ModExp(c1, q - 1 - x, q)) % q;
            return (int)m0;

        }
        public long ModExp(long b, long e, long m)
        {
            if (m == 1)
            {
                return 0;
            }
            long r = 1;
            b = b % m;
            for (; e > 0; e >>= 1)
            {
                if ((e & 1) == 1)
                {
                    r = (r * b) % m;
                }
                b = (b * b) % m;
            }
            return r;
        }
        public int ModPower(int m1, int m2, int m3)
        {

            int result = 1;
            for (; m2 > 0; m2 /= 2)
            {
                if (m2 % 2 == 1) { result = (result * m1) % m3; }
                m1 = (m1 * m1) % m3;
            }
            return result;

        }

    }
}
