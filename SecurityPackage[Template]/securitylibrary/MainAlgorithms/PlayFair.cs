using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        /*
         make class of matrix contain dictionary and list of list of character
         */
        public class newmatrix
        {
            public Dictionary<char, Tuple<int, int>> dictionaryelements;
            public List<List<char>> allmatrix;
        }
        public string Decrypt(string cipherText, string key)
        {
            string temp;
            temp = cipherText.ToLower();
            int moflag = 0,counter=0;
            bool flag = false;
            newmatrix matrix = xFunc(newKey(key));
            string FinalPlanTxt = "";
            int momoa = 0;
            while (!flag)
            {
                flag = true;
                string Plan = "";
                while (true)
                {
                    char charater1 = temp[momoa];
                    char character2 = temp[momoa+ 1];
                    
                    if (matrix.dictionaryelements[charater1].Item1 == matrix.dictionaryelements[character2].Item1)
                    {
                        moflag = 1;
                        Plan =Plan+ matrix.allmatrix[matrix.dictionaryelements[charater1].Item1][(matrix.dictionaryelements[charater1].Item2 + 4) % 5];
                        Plan = Plan + matrix.allmatrix[matrix.dictionaryelements[character2].Item1][(matrix.dictionaryelements[character2].Item2 + 4) % 5];
                    }
                    else if (matrix.dictionaryelements[charater1].Item2 == matrix.dictionaryelements[character2].Item2)
                    {

                        Plan = Plan + matrix.allmatrix[(matrix.dictionaryelements[charater1].Item1 + 4) % 5][matrix.dictionaryelements[charater1].Item2];
                        Plan = Plan + matrix.allmatrix[(matrix.dictionaryelements[character2].Item1 + 4) % 5][matrix.dictionaryelements[character2].Item2];
                        moflag =2;
                    }
                    else if(matrix.dictionaryelements[charater1].Item2 != matrix.dictionaryelements[character2].Item2&& matrix.dictionaryelements[charater1].Item1 != matrix.dictionaryelements[character2].Item1)
                    {
                        Plan = Plan + matrix.allmatrix[matrix.dictionaryelements[charater1].Item1][matrix.dictionaryelements[character2].Item2];
                        Plan = Plan + matrix.allmatrix[matrix.dictionaryelements[character2].Item1][matrix.dictionaryelements[charater1].Item2];
                        moflag = 3;
                    }
                    momoa += 2;
                    if (momoa< cipherText.Length)
                    {
                        continue;
                    }
                    else
                    {
                        break;
                    }
                    

                }


                string answer = Plan;
                string moo = answer;
                int i = 0, h = 0;
                //if we have x in the last
                if (moo[moo.Length - 1] == 'x')
                {
                    moo = moo.Remove(moo.Length - 1);
                }
                while (true)
                {
                    if (Plan[i] == 'x')
                    {
                        h = 1;
                    }
                    if(h==1)
                    {
                        if (Plan[i - 1] == Plan[i + 1])
                        {
                            if (i + counter < answer.Length )
                            {
                                if ((i-1)%2==0)
                                {
                                    moo = moo.Remove(i + counter, 1);
                                    counter--;
                                }
                            }
                        }
                        h = 0;
                    }
                    i++;
                    if (i < moo.Length)
                    {
                        continue;
                    }

                    else
                    {
                        break;
                    }
                }
                FinalPlanTxt+= moo;
            }

           
            return FinalPlanTxt;
        }

        public string Encrypt(string plainText, string key)
        {
            newmatrix mo = xFunc(newKey(key));
            string CommonText = "";
            string temp = plainText;
            int k = 0;
            int flag = 0;
            while(true)
            {   if(temp[k] == temp[k + 1])
                {
                    flag = 1;
                }    
                if (flag==1)
                {
                    temp = temp.Substring(0, k + 1) + 'x' + temp.Substring(k + 1);
                    flag = 0;
                }
                k += 2;
                if (k<plainText.Length-1)
                {
                    continue;
                }
                else
                {
                    break;
                }
               
            }
            if (temp.Length % 2 == 1)
            {
                temp += 'x';
            }
            int flag2 = 0;
            int momo = 0;
            while(true)
            {
                char c1 = temp[momo];
                char c2 = temp[momo + 1];
                //option1 same row
                if (mo.dictionaryelements[c1].Item1 == mo.dictionaryelements[c2].Item1) 
                {  
                    flag2= 2;
                }
                //option1 same column
                else if (mo.dictionaryelements[c1].Item2 == mo.dictionaryelements[c2].Item2)
                {
                    flag2 = 1;
                }
                //option 3
                else if(mo.dictionaryelements[c1].Item1 != mo.dictionaryelements[c2].Item1&& mo.dictionaryelements[c1].Item2 != mo.dictionaryelements[c2].Item2)
                {
                    flag2 = 3;
                }
                
                if(flag2==2)
                    {
                        CommonText =CommonText+ mo.allmatrix[mo.dictionaryelements[c1].Item1][(mo.dictionaryelements[c1].Item2 + 1) % 5];
                        CommonText =CommonText+ mo.allmatrix[mo.dictionaryelements[c2].Item1][(mo.dictionaryelements[c2].Item2 + 1) % 5];
                        flag2 = 0;
                    }
                else if(flag2==1)
                    {
                        CommonText = CommonText + mo.allmatrix[(mo.dictionaryelements[c1].Item1 + 1) % 5][mo.dictionaryelements[c1].Item2];
                        CommonText = CommonText + mo.allmatrix[(mo.dictionaryelements[c2].Item1 + 1) % 5][mo.dictionaryelements[c2].Item2];
                        flag2 = 0;

                    }
                    else if(flag2==3)
                    {
                        CommonText = CommonText + mo.allmatrix[mo.dictionaryelements[c1].Item1][mo.dictionaryelements[c2].Item2];
                        CommonText = CommonText + mo.allmatrix[mo.dictionaryelements[c2].Item1][mo.dictionaryelements[c1].Item2];
                        flag2 = 0;
                    }
                momo += 2;
                if(momo<temp.Length)
                {
                    continue;
                }
                else
                {
                    break;
                }
            }
            return CommonText.ToUpper();
            // case 1 add x if we have any duplicated alphabet between the duplicate alphabet
            /*           old plan text
             0  1  2  3  4  5  6  7  8  9  10   11   12
             c  o  m  m  u  n  i  c  a  t  i    o    n
            we compare i and i+1 and every time we increment i by 2 because we divided sequence by 2 
            c and o not equal 
            m and m equal then add x ==>mx
            and so on{co,mx,mu,ni,ca,ti,on} and the last index we compare is the item before the last index length-1
                          new plantext
            0  1  2   3  4  5  6  7  8  9  10   11   12   13  
             c  o  m  x  m  u  n  i  c  a  t     i    o    n
             */

            
            //case 2 if we have a last alphabet alone we add after it x
            // make sure that new 
          
        }
        public HashSet<char> newKey(string key)
        {
            /*in this function take a key and add it in the hashtable to makesure that we
            don't have any duplicate alphapet in the key*/
            int i = 0,j = 0;
            HashSet<char> newkeywithoutrepeatedalpha = new HashSet<char>();
            HashSet<char> temp = new HashSet<char>();
            //add the key in the hash map and if we have j replace it to i
            string englishlpha;
            englishlpha = "abcdefghiklmnopqrstuvwxyz";
            while (true)
            {
                if (key[i] != 'j')//if no equal j add it
                {
                    newkeywithoutrepeatedalpha.Add(key[i]);//if equal j replace it to i
                }
                else if(key[i] == 'j')
                {
                    newkeywithoutrepeatedalpha.Add('i');
                }
                i++;
                if(i == key.Length)
                {
                    break;
                }
            }

            while(true)
            { 
                newkeywithoutrepeatedalpha.Add(englishlpha[j]);
                j++;
            if(j==25)
            {
                break;
            }
            }
            temp = newkeywithoutrepeatedalpha;

            return temp;

        }
        public newmatrix xFunc(HashSet<char> newkey)
        {
            /*make matrix with two key in dictionary with column number and row number take a hashset
            and add it in dectionary and make a matrix by using the list of list of character */
            int ckecknumberofiteminmatrix = 0;
            int i = 0;
            Dictionary<char, Tuple<int, int>> Matrix = new Dictionary<char, Tuple<int, int>>();

            /*                 #   Example of matrix of key  #  
                               i/k 0   1   2   3   4  
                                0  p   l   a   y   f  temp in first time
                                1  i   r   e   x   m  temp in second time
                                2  b   c   d   g   h  temp in third time
                                3  k   n   o   q   s  temp in fourth time
                                4  t   u   v   w   z  temp in fifth time
             */
            int fla = 0;
            HashSet<char> newkeywithoutrepeatedalphakey = new HashSet<char>();
            newkeywithoutrepeatedalphakey = newkey;
            List<List<char>> allofMatrix = new List<List<char>>();
           while(true)
            {
                /*here we make a list of character as a new temporory and
                add it in new matrix contain dectionary make it matrix
                example  
                          p   l   a   y   f
                          i   r   e   x   m
                          b   c   d   g   h
                          k   n   o   q   s 
                          t   u   v   w   z 
                */

                List<char> insidelist = new List<char>();
                List<char> list = new List<char>();
                int k = 0;
                for (;k<5;)
                {
                    if (25>ckecknumberofiteminmatrix)
                    {
                        list.Add(newkeywithoutrepeatedalphakey.ElementAt(ckecknumberofiteminmatrix));
                        insidelist = list;
                        Matrix.Add(newkeywithoutrepeatedalphakey.ElementAt(ckecknumberofiteminmatrix), new Tuple<int, int>(i, k));
                        /*     i/k 0   1   2   3   4  
                                0  p   l   a   y   f  temp in first time
                                1  i   r   e   x   m  temp in second time
                                2  b   c   d   g   h  temp in third time
                                3  k   n   o   q   s  temp in fourth time
                                4  t   u   v   w   z  temp in fifth time
                    */
                        
                        ckecknumberofiteminmatrix++;
                    }
                    k++;
                }

                allofMatrix.Add(list);
                i++;
                if(i==5)
                {
                    break;
                }
            }
            /*    
                               i/k 0   1   2   3   4  
                                0  p   l   a   y   f  temp in first time
                                1  i   r   e   x   m  temp in second time
                                2  b   c   d   g   h  temp in third time
                                3  k   n   o   q   s  temp in fourth time
                                4  t   u   v   w   z  temp in fifth time
             */
            //make a object form class new matrix and save dictionary and list of list of caracter
            newmatrix mmatrix = new newmatrix();
            Dictionary<char, Tuple<int, int>> Matrixtemp = new Dictionary<char, Tuple<int, int>>();
            Matrixtemp = Matrix;
            mmatrix.allmatrix = allofMatrix;
            mmatrix.dictionaryelements = Matrixtemp;
            return mmatrix;
        }
        
    } 
}