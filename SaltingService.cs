using System.Net.Mime;
using System.Net.NetworkInformation;
using Newtonsoft.Json;

//Null reference warnings
#pragma warning disable CS8600
#pragma warning disable CS8601
#pragma warning disable CS8602
#pragma warning disable CS8604

namespace FileLocker
{
    public class Salter
    {
        public static Salter SaltService = new();


        /// <summary>
        /// int a Hash generated by the EncryptionService.GetHash(string) the hash is of the filename without extension, 
        /// first string in the tuple is the salt in Base64, 
        /// the second is the original file location
        /// the third is a HashStore object for the Password for decryption
        /// </summary>
        /// <param name="SaltDB"></param>
        /// <returns></returns>
        public Dictionary<int, (string, string, HashStore)> SaltDB = new();

        private protected string CorrectDBPassword = "";
        private protected byte[] DBKey = new byte[1];
        private protected byte[] DBIV = new byte[1];
        private Salter()
        {
            if (File.Exists("DBHash.edb"))
            {

                bool cont = false;
                string json = File.ReadAllText("DBHash.edb");
                HashStore HS = JsonConvert.DeserializeObject<HashStore>(json);
                while (!cont)
                {
                    System.Console.WriteLine("Enter your password for the Salting and Hashing Service");
                    string pass = Console.ReadLine();
                    Console.Clear();
                    string TryHash = BCrypt.Net.BCrypt.HashPassword(pass, HS.Salt);
                    if (TryHash == HS.PasswordHash)
                    {
                        cont = true;
                        System.Console.WriteLine("Access Granted, Salting Service loading");
                        CorrectDBPassword = pass;
                    }
                    else
                    {
                        System.Console.WriteLine("Incorrect Password");
                        Environment.Exit(0);
                    }
                }

            }
            else
            {
                System.Console.WriteLine("Enter a Password for the Salting Service This will be a global password for all salts and password hashes (Dont lose it!)");
                string pass = Console.ReadLine();
                string s = BCrypt.Net.BCrypt.GenerateSalt(16);
                string hashedP = BCrypt.Net.BCrypt.HashPassword(pass, s);
                HashStore HS = new("SaltDBHash", hashedP, s);
                string json = JsonConvert.SerializeObject(HS, Formatting.Indented);
                File.WriteAllText("DBHash.edb", json);
                CorrectDBPassword = pass;
                Console.Clear();
            }

            byte[] DBSalt;
            if (File.Exists("DBSalt.txt"))
            {
                string b64Salt = File.ReadAllText("DBSalt.txt");
                DBSalt = Convert.FromBase64String(b64Salt);
            }
            else
            {
                DBSalt = EncryptionService.GenSalt(16);
                File.WriteAllText("DBSalt.txt", Convert.ToBase64String(DBSalt));
            }

            if (File.Exists("SaltDB.edb"))
            {
                string encjson = File.ReadAllText("SaltDB.edb");
                (byte[], byte[]) KeyIV = EncryptionService.GenerateKeyAndIV(CorrectDBPassword, DBSalt, 32, 16, 10000);
                DBKey = KeyIV.Item1;
                DBIV = KeyIV.Item2;
                string json = EncryptionService.Decrypt(Convert.FromBase64String(encjson), DBKey, DBIV);
                SaltDB = JsonConvert.DeserializeObject<Dictionary<int, (string, string, HashStore)>>(json);
            }
            else
            {
                (byte[], byte[]) KeyIV = EncryptionService.GenerateKeyAndIV(CorrectDBPassword, DBSalt, 32, 16, 10000);
                DBKey = KeyIV.Item1;
                DBIV = KeyIV.Item2;
            }
        }


        /// <summary>
        /// File Hash should be generated by EncryptionService.GetHash(string).
        /// Salt should be from EncryptionService.GenSalt(int SaltLength)
        /// </summary>
        /// <param name="FileHash"></param>
        /// <param name="SaltB64"></param>
        /// <param name="FileLocation"></param>
        /// <param name="HS"></param>
        /// <returns></returns>
        public bool AddSalt(int FileHash, string SaltB64, string FileLocation, HashStore HS)
        {
            if (SaltDB.TryAdd(FileHash, (SaltB64, FileLocation, HS)))
            {
                SaveDB();
                return true;
            }
            else System.Console.WriteLine("Failed to add a files salt to the db, possible duplicate FileName");
            return false;
        }

        public void SaveDB()
        {
            string json = JsonConvert.SerializeObject(SaltDB, Formatting.Indented);
            byte[] EncDB = EncryptionService.Encrypt(json, DBKey, DBIV);
            File.WriteAllText("SaltDB.edb", Convert.ToBase64String(EncDB));
        }

        public void WipeDB()
        {
            System.Console.WriteLine("Are you sure you want to wipe the SaltDB? All Files will be unaccessable if theyre encrypted (y/n)");
            string input = Console.ReadLine().ToLower();
            if (input == "y" || input == "1" || input == "true" || input == "yes")
            {
                SaltDB = new();
                SaveDB();
            }
        }
    }
}