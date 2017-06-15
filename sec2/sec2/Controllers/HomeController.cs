
using sec2.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Mvc;

namespace sec2.Controllers
{
    public class HomeController : Controller
    {

        public ActionResult Index()
        {
            return View();
        }

        public ActionResult Encrypt(string secretText, string userName, string password)
        {
            var encryptionKey = userName + password;
            var salt = new byte[32];
            using (Aes myAes = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password, salt);
                myAes.Key = pdb.GetBytes(myAes.KeySize / 8);
                myAes.GenerateIV();

                byte[] encrypted = EncryptStringToBytes(secretText, myAes.Key, myAes.IV);

                StringBuilder s = new StringBuilder();
                foreach (byte item in encrypted)
                {
                    s.Append(item.ToString("X2") + " ");
                }

                EncryptedData secretInfo = new EncryptedData();
                secretInfo.encryptedText = encrypted;
                secretInfo.user = userName;
                secretInfo.vector = myAes.IV;
                secretInfo.salt = salt;
                using (Context context = new Context())
                {
                    context.EncryptedData.Add(secretInfo);
                    context.SaveChanges();
                }
            }
            return View("Index");
        }

        public ActionResult Decrypt(string userName, string password)
        {
            var encryptionKey = userName + password;
            byte[] encryptedText = null;
            byte[] initialiationVector = null;
            var decryptedText = "";
            Rfc2898DeriveBytes pdb;
            using (Context context = new Context())
            {
                EncryptedData info = context.EncryptedData.Where(u => u.user.Equals(userName)).SingleOrDefault();
                pdb = new Rfc2898DeriveBytes(password, info.salt);
                encryptedText = info.encryptedText;
                initialiationVector = info.vector;
            }
            using (Aes myRijndael = Aes.Create())
            {
                decryptedText = DecryptStringFromBytes(encryptedText, pdb.GetBytes(myRijndael.KeySize / 8), initialiationVector);
            }
            return View("Index", null, decryptedText);
        }

        private byte[] EncryptStringToBytes(string plainText, byte[] Key, byte[] IV)
        {
            byte[] encrypted;
            using (Aes myAes = Aes.Create())
            {
                myAes.Key = Key;
                myAes.IV = IV;
                myAes.Mode = CipherMode.CBC;
                myAes.Padding = PaddingMode.Zeros;

                ICryptoTransform encryptor = myAes.CreateEncryptor(myAes.Key, myAes.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }


            // Return the encrypted bytes from the memory stream.
            return encrypted;

        }

        private string DecryptStringFromBytes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            string plaintext = null;

            using (Aes myAes = Aes.Create())
            {
                myAes.Key = Key;
                myAes.IV = IV;
                myAes.Mode = CipherMode.CBC;
                myAes.Padding = PaddingMode.Zeros;

                ICryptoTransform decryptor = myAes.CreateDecryptor(myAes.Key, myAes.IV);

                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }
            return plaintext.ToString();
        }
    }
}