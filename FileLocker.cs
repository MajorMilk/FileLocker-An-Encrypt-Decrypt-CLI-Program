using System.Collections;

namespace FileLocker
{
    public static class FileLocker
    {

        /// <summary>
        /// Decrypts an entire Directory with the same password and salt, faster than calling Encrypt and Decrypt on all files individually.
        /// </summary>
        /// <param name="Dir"></param>
        /// <param name="Password"></param>
        /// <param name="DeleteOriginalFiles"></param>
        public static void DecryptDir(string Dir, string Password, bool DeleteOriginalFiles = false)
        {
            string[] Files = new string[1];
            try
            {
                Files = Directory.GetFiles(Dir, "*.enc");
            }
            catch (Exception e)
            {

                System.Console.WriteLine($"Failed to get files: {e.Message}");
            }

            if (Salter.SaltService.SaltDB.TryGetValue(EncryptionService.GetHash(Dir), out (string, string, HashStore) PHashAndSalt))
            {
                string HashedP = BCrypt.Net.BCrypt.HashPassword(Password, PHashAndSalt.Item3.Salt);
                if (HashedP == PHashAndSalt.Item3.PasswordHash)
                {
                    var KeyIV = EncryptionService.GenerateKeyAndIV(Password, Convert.FromBase64String(PHashAndSalt.Item1), 32, 16, 10000);

                    foreach (string file in Files)
                    {
                        if (Path.GetDirectoryName(file) != Dir) continue;
                        else
                        {
                            if (Salter.SaltService.SaltDB.TryGetValue(EncryptionService.GetHash(Path.GetFileNameWithoutExtension(file)), out (string, string, HashStore) PassHashAndSalt))
                            {
                                byte[] EncBytes = File.ReadAllBytes(file);

                                string UnEncryptedB64 = EncryptionService.Decrypt(EncBytes, KeyIV.Item1, KeyIV.Item2);

                                EncBytes = Convert.FromBase64String(UnEncryptedB64);

                                File.WriteAllBytes(PassHashAndSalt.Item2, EncBytes);

                                if (DeleteOriginalFiles)
                                {
                                    File.Delete(file);
                                }
                                Salter.SaltService.SaltDB.Remove(EncryptionService.GetHash(Path.GetFileNameWithoutExtension(file)));
                            }
                            else
                            {
                                System.Console.WriteLine($"Salt Not Found in the DB for: {file}");
                            }
                        }
                    }
                }
                else
                {
                    System.Console.WriteLine("Incorrect Password");
                }
                Salter.SaltService.SaltDB.Remove(EncryptionService.GetHash(Dir));
                Salter.SaltService.SaveDB();
            }
            else
            {
                System.Console.WriteLine("Could not find that the Dir has been encrypted (no entry in the SaltDB)");
            }
        }



        /// <summary>
        /// Encrypts an entire Directory with the same password and salt, faster than calling Encrypt and Decrypt on all files individually.
        /// </summary>
        /// <param name="Dir"></param>
        /// <param name="password"></param>
        /// <param name="DeleteOriginalFiles"></param>
        public static void EncryptDir(string Dir, string password, bool DeleteOriginalFiles = false)
        {
            string[] Files = new string[1];
            try
            {
                Files = Directory.GetFiles(Dir);
            }
            catch (Exception e)
            {

                System.Console.WriteLine($"Failed to get files: {e.Message}");
            }

            string PSalt = BCrypt.Net.BCrypt.GenerateSalt(16);
            string HashedP = BCrypt.Net.BCrypt.HashPassword(password, PSalt);

            HashStore FilePasswordHash = new(Dir, HashedP, PSalt);

            byte[] FileSalt = EncryptionService.GenSalt(16);

            var KeyIV = EncryptionService.GenerateKeyAndIV(password, FileSalt, 32, 16, 10000);

            Salter.SaltService.AddSalt(EncryptionService.GetHash(Dir), Convert.ToBase64String(FileSalt), Dir, FilePasswordHash);


            foreach (string file in Files)
            {
                if (Path.GetDirectoryName(file) != Dir) continue;
                else
                {
                    Salter.SaltService.AddSalt(EncryptionService.GetHash(Path.GetFileNameWithoutExtension(file)), Convert.ToBase64String(FileSalt), file, FilePasswordHash);

                    byte[] OriginalFile = File.ReadAllBytes(file);
                    string B64Data = Convert.ToBase64String(OriginalFile);
                    OriginalFile = new byte[1];

                    byte[] EncData = EncryptionService.Encrypt(B64Data, KeyIV.Item1, KeyIV.Item2);

                    string CorrectedPath = Path.ChangeExtension(file, ".enc");

                    File.WriteAllBytes(CorrectedPath, EncData);
                    if (DeleteOriginalFiles)
                    {
                        File.Delete(file);
                    }
                }




            }
        }
        /// <summary>
        /// Encryps a file with AES-256, Creates a new file with the same name with an extension of .enc
        /// </summary>
        /// <param name="FileLocation"></param>
        /// <param name="password"></param>
        public static void EncryptFile(string FileLocation, string password, bool DeleteOriginalFile = false)
        {
            string FileName = Path.GetFileNameWithoutExtension(FileLocation);
            int FileHash = EncryptionService.GetHash(FileName);
            byte[] FileSalt = EncryptionService.GenSalt(16);

            string PasswordSalt = BCrypt.Net.BCrypt.GenerateSalt(16);
            string HashedP = BCrypt.Net.BCrypt.HashPassword(password, PasswordSalt);
            HashStore hs = new(FileName, HashedP, PasswordSalt);

            if (!Salter.SaltService.AddSalt(FileHash, Convert.ToBase64String(FileSalt), FileLocation, hs))
            {
                System.Console.WriteLine("Failed To Salt, Hash, and encrypt");
                return;
            }

            var KeyIV = EncryptionService.GenerateKeyAndIV(password, FileSalt, 32, 16, 10000);


            string EncryptedLocation = Path.ChangeExtension(FileLocation, ".enc");

            string OriginalBytes = Convert.ToBase64String(File.ReadAllBytes(FileLocation));

            byte[] EncBytes = EncryptionService.Encrypt(OriginalBytes, KeyIV.Item1, KeyIV.Item2);

            File.WriteAllBytes(EncryptedLocation, EncBytes);
            if (DeleteOriginalFile)
            {
                File.Delete(FileLocation);
            }
        }


        /// <summary>
        /// The File path you provide should be the file path of the .enc file, Only the FileName is used for hashing so the extension is irrelevent.
        /// Although there must be a .enc file containing the encryped data in the same directory as the given file path with the same file name
        /// </summary>
        /// <param name="FilePath"></param>
        /// <param name="password"></param>
        public static void DecryptFile(string FilePath, string password, bool DeleteOriginalFile = false)
        {
            string CorrectedPath = Path.ChangeExtension(FilePath, ".enc");
            string FileName = Path.GetFileNameWithoutExtension(FilePath);
            if (Salter.SaltService.SaltDB.TryGetValue(EncryptionService.GetHash(FileName), out (string, string, HashStore) SaltLocationAndHash))
            {
                string HashedP = BCrypt.Net.BCrypt.HashPassword(password, SaltLocationAndHash.Item3.Salt);
                if (HashedP != SaltLocationAndHash.Item3.PasswordHash)
                {
                    System.Console.WriteLine("Incorrect Password. Decryption Failed");
                    return;
                }
                if (!File.Exists(CorrectedPath))
                {
                    System.Console.WriteLine($"File not found... {CorrectedPath}");
                    return;
                }
                byte[] EncBytes = File.ReadAllBytes(CorrectedPath);

                var KeyIV = EncryptionService.GenerateKeyAndIV(password, Convert.FromBase64String(SaltLocationAndHash.Item1), 32, 16, 10000);

                string UnEncryptedBytesB64 = EncryptionService.Decrypt(EncBytes, KeyIV.Item1, KeyIV.Item2);

                EncBytes = Convert.FromBase64String(UnEncryptedBytesB64);

                File.WriteAllBytes(SaltLocationAndHash.Item2, EncBytes);
                if (DeleteOriginalFile)
                {
                    File.Delete(CorrectedPath);
                }
                Salter.SaltService.SaltDB.Remove(EncryptionService.GetHash(FileName));
                Salter.SaltService.SaveDB();
                return;
            }
            System.Console.WriteLine("Salt not found, likley, the file has not been encryped yet");
        }
    }
}