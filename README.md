# FileLocker An Encrypt/Decrypt CLI Program
 Uses AES-256 to encrypt and decrypt files and directories, and uses BCrypt for password Hashing.

## Requirements
 Uses Newtonsoft.Json for storing data
 BCrypt.Net for hashing passwords
 and CommandLineParser for accepting command line arguments.

## Info
 The JSON for the SaltDB is encrypted using a password set at the time of the first run, to reset the password, simply delete DBHash.edb and SaltDB.edb, Keep in mind you'll no longer be able to decrypt the SaltDB after this, that's why you should just delete it after resetting the password.

 There is only one unencrypted hash for the whole program and that is for the SaltDB's hash, there's also salt for generating the Key and IV for the SaltDB's decryption that is unencrypted, for this reason your password for the SaltDB should be secure, although there is no enforcement on that.

 Key and IV generation is done through the Rfc2898DeriveBytes class with the SHA-256 Hash Algorithm.

 The SaltService is simply a dictionary that links a filename's (without extension) hash to a tuple that stores file info, encryption salt, and a hash for the password used for encryption. This data is all encrypted.

 After a file is unencrypted, it is removed from the SaltService, the same goes for a directory.

## Arguments
 -f or --file : this tells the program that it will be working with a single file
 -d or --dir : this tells the program that it will be working with a whole directory.
 -e or --encrypt : this tells the program to encrypt the file or dir
 -u or --unencrypt : this tell the program to unencrypt the file or dir

 -i or --input : This is the main input for the program, it should be the path of the file or directory in question. example: C:\TestFolder or C:\TestFolder\TestFile.txt
 

 
