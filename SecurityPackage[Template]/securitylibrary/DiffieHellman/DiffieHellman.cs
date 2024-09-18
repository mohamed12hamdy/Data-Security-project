using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            List<int> result = new List<int>();
            int YA= power(alpha, xa, q);
            int YB = power(alpha, xb, q);
            int mo1 = power(YB, xa, q);
            int mo2 = power(YA, xb, q);
            result.Add(mo1);
            result.Add(mo2);
            return result;
        }
        public int power(int a, int b, int c)
        {
            int result = 1;
            int cr7; 
            cr7= 0;
            while(cr7 < b)
            {
                result = (result * a) % c;
                cr7++;
            }
            return result;
        }
    }
}