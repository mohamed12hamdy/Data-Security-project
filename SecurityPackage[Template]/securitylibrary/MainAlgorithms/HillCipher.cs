using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using MathNet.Numerics.LinearAlgebra;
using MathNet.Numerics.LinearAlgebra.Double;


namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public List<double> intToDouble(List<int> i)
        {
            List<double> d = new List<double>();
            foreach (int j in i)
                d.Add((double)j);
            return d;
        }


        public int det(Matrix<double> M)
        {
            double A = M[0, 0] * (M[1, 1] * M[2, 2] - M[1, 2] * M[2, 1]) -
                       M[0, 1] * (M[1, 0] * M[2, 2] - M[1, 2] * M[2, 0]) +
                       M[0, 2] * (M[1, 0] * M[2, 1] - M[1, 1] * M[2, 0]);
            int AI;
            if ((int)A % 26 >= 0)
                AI = (int)A % 26;
            else
                AI = (int)A % 26 + 26;
            for (int i = 0; i < 26; i++)
            {
                if (AI * i % 26 == 1)
                    return i;
            }
            return -1;
        }



        public Matrix<double> ModMinorCofactor(Matrix<double> M, int A)
        {
            Matrix<double> resMat = DenseMatrix.Create(3, 3, 0.0);

            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    int x, y, x1, y1;

                    if (i == 0)
                        x = 1;
                    else
                        x = 0;

                    if (j == 0)
                        y = 1;
                    else
                        y = 0;

                    if (i == 2)
                        x1 = 1;
                    else
                        x1 = 2;

                    if (j == 2)
                        y1 = 1;
                    else
                        y1 = 2;


                    double r = ((M[x, y] * M[x1, y1] - M[x, y1] * M[x1, y]) * Math.Pow(-1, i + j) * A) % 26;
                    if (r >= 0)
                        resMat[i, j] = r;
                    else
                        resMat[i, j] = r + 26;

                }
            }
            return resMat;
        }


       


        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            // Loop through each possible letter for the first character of the key
            for (int i = 0; i < 26; i++)
            {
                // Loop through each possible letter for the second character of the key
                for (int j = 0; j < 26; j++)
                {
                    // Loop through each possible letter for the third character of the key
                    for (int k = 0; k < 26; k++)
                    {
                        // Loop through each possible letter for the fourth character of the key
                        for (int l = 0; l < 26; l++)
                        {
                            // Create a new key consisting of the current letters
                            List<int> key = new List<int> { i, j, k, l };

                            // Encrypt the plainText using the current key
                            List<int> encrypted = Encrypt(plainText, key);

                            // If the encrypted text matches the cipherText, we've found the key!
                            if (encrypted.SequenceEqual(cipherText))
                                return key;
                        }
                    }
                }
            }

            // If we were unable to find a matching key, throw an exception
            throw new InvalidAnlysisException();
        }



        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            List<double> doubleKey = intToDouble(key);
            List<double> doubleCipher = intToDouble(cipherText);
            List<int> finalRes = new List<int>();

            int row = (int)Math.Pow(key.Count, 0.5);
            int keyCol = key.Count / row;
            int cipherCol = cipherText.Count / row;

            Matrix<double> keyMatrix = DenseMatrix.OfColumnMajor(row, keyCol, doubleKey);
            Matrix<double> textMatrix = DenseMatrix.OfColumnMajor(row, cipherCol, doubleCipher);



            if (keyMatrix.ColumnCount == 3)
                keyMatrix = ModMinorCofactor(keyMatrix.Transpose(), det(keyMatrix));
            else
                keyMatrix = keyMatrix.Inverse();


            string intKeyMatrix = Math.Abs((int)keyMatrix[1, 1]).ToString();
            string doubleKeyMatrix = Math.Abs((double)keyMatrix[1, 1]).ToString();

            if (intKeyMatrix != doubleKeyMatrix)
                throw new SystemException();

            for (int i = 0; i < textMatrix.ColumnCount; i++)
            {
                List<double> Res = ((((textMatrix.Column(i)).ToRowMatrix() * keyMatrix) % 26).Enumerate().ToList());
                foreach (double r in Res)
                {
                    int x;

                    if (r >= 0)
                        x = (int)r;
                    else
                        x = (int)r + 26;
                    finalRes.Add(x);
                }
            }

            return finalRes;
        }



        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            //declare and initialize variables
            List<double> keyDouble = intToDouble(key);
            List<double> textDouble = intToDouble(plainText);
            List<int> result = new List<int>();

            int row = (int)Math.Pow(key.Count, 0.5);
            int keyCol = key.Count / row;
            int textCol = plainText.Count / row;

            Matrix<double> keyMatrix = DenseMatrix.OfColumnMajor(row, keyCol, keyDouble);
            Matrix<double> textMatrix = DenseMatrix.OfColumnMajor(row, textCol, textDouble);
            Matrix<double> mul;
            for (int i = 0; i < textMatrix.ColumnCount; i++)
            {

                mul = textMatrix.Column(i).ToRowMatrix() * keyMatrix;

                List<double> multResult = ((mul % 26).Enumerate()).ToList();

                foreach (double j in multResult)
                    result.Add((int)j);
            }
            return result;
        }

        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }


        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            List<double> doubleCipher = intToDouble(cipher3);
            List<double> doublePlain = intToDouble(plain3);
            List<int> Key = new List<int>();
            List<double> doubleKey;



            int row = (int)Math.Pow(cipher3.Count, 0.5);
            int col = plain3.Count / row;

            Matrix<double> cipherMatrix = DenseMatrix.OfColumnMajor(row, col, doubleCipher);
            Matrix<double> plainMatrix = DenseMatrix.OfColumnMajor(row, col, doublePlain);
            Matrix<double> KeyMatrix;

            plainMatrix = ModMinorCofactor(plainMatrix.Transpose(), det(plainMatrix));
            KeyMatrix = cipherMatrix * plainMatrix;
            doubleKey = KeyMatrix.Transpose().Enumerate().ToList();

            for (int i = 0; i < doubleKey.Count; i++)
                Key.Add((int)doubleKey[i] % 26);

            return Key;

            throw new NotImplementedException();
        }
        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
    }
}
