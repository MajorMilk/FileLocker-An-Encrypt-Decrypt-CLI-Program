using CommandLine;
namespace FileLocker
{
    class Arguments
    {
        [Option('f', "file", Required = false, HelpText = "Toggles Single File mode, if used, the input should be a file location path")]
        public bool FileMode { get; set; } = false;

        [Option('d', "dir", Required = false, HelpText = "Toggles Directory Mode, either -f or -d should be used for each run of this application")]
        public bool DirMode { get; set; } = false;

        [Option('i', "input", Required = true, HelpText = "The input File or Directory Path")]
        public string InputPath { get; set; } = "";

        [Option('e', "encrypt", Required = false, HelpText = "Flag for encryption mode")]
        public bool EncryptMode { get; set; } = false;

        [Option('u', "unencrypt", Required = false, HelpText = "Flag for Decryption")]
        public bool DecryptMode { get; set; } = false;
    }
}