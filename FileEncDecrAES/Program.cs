using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace FileEncDecrAES
{
    class Program
    {
        static void Main(string[] args)
        {
            string fileName, password;
            int userChoise;
            while (true)
            {
                Console.Clear();
                Console.WriteLine("1. Encrypt file");
                Console.WriteLine("2. Decrypt file");
                Console.WriteLine("3. Exit");
                userChoise = Int32.Parse(Console.ReadLine());
                switch (userChoise)
                {
                    case 1:
                        Console.Clear();
                        Console.WriteLine("Enter name of the file");
                        fileName = Console.ReadLine();
                        Console.WriteLine("Enter password for the encryption");
                        password = Console.ReadLine();
                        aesEncrypt(fileName, password);
                        break;
                    case 2:
                        Console.Clear();
                        Console.WriteLine("Enter name of the file");
                        fileName = Console.ReadLine();
                        Console.WriteLine("Enter password for the decryption");
                        password = Console.ReadLine();
                        aesDecrypt(fileName, password);
                        break;
                    case 3:
                        Console.WriteLine("Exiting");
                        Environment.Exit(0);
                        break;
                    default:
                        Console.WriteLine("Enter right choise");
                        break;
                }
            }
        }
        private static void aesEncrypt(string inputFile, string password)
        {
            byte[] salt = generateRandomSalt();
            FileStream fsCrypt = new FileStream(inputFile + ".encrypted", FileMode.Create);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            RijndaelManaged AES = new RijndaelManaged();
            AES.KeySize = 256;
            AES.BlockSize = 128;
            AES.Padding = PaddingMode.PKCS7;

            var key = new Rfc2898DeriveBytes(passwordBytes, salt, 50000);
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);

            AES.Mode = CipherMode.CFB;

            fsCrypt.Write(salt, 0, salt.Length);

            CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateEncryptor(), CryptoStreamMode.Write);

            FileStream fsIn = new FileStream(inputFile, FileMode.Open);

            byte[] buffer = new byte[1048576];
            int read;

            try
            {
                while ((read = fsIn.Read(buffer, 0, buffer.Length)) > 0)
                {
                    cs.Write(buffer, 0, read);
                }

                fsIn.Close();

            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
            finally
            {
                cs.Close();
                fsCrypt.Close();
                AES.Clear();
            }
        }
        private static void aesDecrypt(string inputFile, string password)
        {
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] salt = new byte[32];

            FileStream fsCrypt = new FileStream(inputFile, FileMode.Open);
            fsCrypt.Read(salt, 0, salt.Length);

            RijndaelManaged AES = new RijndaelManaged();
            AES.KeySize = 256;
            AES.BlockSize = 128;
            var key = new Rfc2898DeriveBytes(passwordBytes, salt, 50000);
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);
            AES.Padding = PaddingMode.PKCS7;
            AES.Mode = CipherMode.CFB;

            CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateDecryptor(), CryptoStreamMode.Read);

            FileStream fsOut = new FileStream(inputFile + ".decrypted", FileMode.Create);

            int read;
            byte[] buffer = new byte[1048576];

            try
            {
                while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
                {
                    fsOut.Write(buffer, 0, read);
                }
            }
            catch (CryptographicException ex_CryptographicException)
            {
                Console.WriteLine("CryptographicException error: " + ex_CryptographicException.Message);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }

            try
            {
                cs.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error by closing CryptoStream: " + ex.Message);
            }
            finally
            {
                fsOut.Close();
                fsCrypt.Close();
                AES.Clear();
            }
        }
        private static byte[] generateRandomSalt()
        {
            byte[] data = new byte[32];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                for (int i = 0; i < 10; i++)
                {
                    rng.GetBytes(data);
                }
            }
            return data;
        }
    }
}