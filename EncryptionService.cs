using System.Security.Cryptography;
using System.Text;
namespace FileLocker
{
    public class HashStore
    {
        public string Salt { get; set; }
        public string PasswordHash { get; set; }
        public string UID { get; set; }


        /// <summary>
        /// This is for storing Password Hashes, not for Encryption Salt.
        /// Salt should be generated through BCrypt.Net.BCrypt.GenerateSalt(int length)
        /// Hashes should be generated from BCrypt.Net.BCrypt.HashPassword(string password, string salt)
        /// </summary>
        /// <param name="uid"></param>
        /// <param name="PHash"></param>
        /// <param name="salt"></param>
        public HashStore(string uid, string PHash, string salt)
        {
            UID = uid;
            PasswordHash = PHash;
            Salt = salt;
        }

        public override string ToString()
        {
            return $"UID: {UID} || Salt: {Salt} || PasswordHash: {PasswordHash}";
        }
    }

    public static class EncryptionService
    {

        public static int GetHash(string input)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(input);
            byte[] hashBytes = SHA256.HashData(bytes);

            // Convert the hashBytes to an integer (you can choose a different method if needed)
            int hash = BitConverter.ToInt32(hashBytes, 0);

            return hash;
        }

        /// <summary>
        /// Generates salt for AES Key and IV Generation
        /// </summary>
        /// <param name="SizeInBytes"></param>
        /// <returns></returns>
        public static byte[] GenSalt(int SizeInBytes)
        {
            byte[] salt = new byte[SizeInBytes];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }
            return salt;
        }


        /// <summary>
        /// For AES-256, 16byte IV and 32 byte key
        /// </summary>
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <param name="keySizeInBytes"></param>
        /// <param name="ivSizeInBytes"></param>
        /// <param name="iterationCount"></param>
        /// <returns></returns>
        public static (byte[], byte[]) GenerateKeyAndIV(string password, byte[] salt, int keySizeInBytes, int ivSizeInBytes, int iterationCount)
        {
            using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterationCount, HashAlgorithmName.SHA256))
            {
                byte[] key = pbkdf2.GetBytes(keySizeInBytes);
                byte[] iv = pbkdf2.GetBytes(ivSizeInBytes);
                return (key, iv);
            }
        }


        /// <summary>
        /// Encrypts a string into a byte[] using AES
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <returns></returns>
        public static byte[] Encrypt(string plainText, byte[] key, byte[] iv)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                    }
                    return msEncrypt.ToArray();
                }
            }
        }

        /// <summary>
        /// Decrypts an AES encrypted byte[] into a string
        /// </summary>
        /// <param name="encryptedData"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <returns></returns>
        public static string Decrypt(byte[] encryptedData, byte[] key, byte[] iv)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(encryptedData))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
        }

    }
}
