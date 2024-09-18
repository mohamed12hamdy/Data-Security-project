using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary.DiffieHellman;
using SecurityLibrary.AES;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public DiffieHellman.DiffieHellman objectmo = new DiffieHellman.DiffieHellman();
        public AES.ExtendedEuclid exx = new AES.ExtendedEuclid();
        public int Encrypt(int p, int q, int M, int e)
        {
            int m= p * q;
            int memo; 
            memo = objectmo.power(M, e, m);
            memo=memo% m;
            return memo;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int m2 = p * q;
            int no = (p - 1);
            no=no* (q - 1);
            e = exx.GetMultiplicativeInverse(e, no);
            int cd; 
            cd= objectmo.power(C, e, m2);
            return cd;
        }
    }
}
