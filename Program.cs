using FileLocker;
using CommandLine;



Parser.Default.ParseArguments<Arguments>(args)
    .WithParsed<Arguments>(arguments =>
    {
        if (arguments.DirMode && arguments.FileMode)
        {
            System.Console.WriteLine("Cannot use both File mode and Dir mode at the same time");
            Environment.Exit(0);
        }
        if (!(arguments.FileMode || arguments.DirMode))
        {
            System.Console.WriteLine("Must specify mode to use (-f for individual files, or -d for an entire diectory)");
            Environment.Exit(0);
        }
        if (arguments.EncryptMode && arguments.DecryptMode)
        {
            System.Console.WriteLine("Cannot Encrypt and Decrypt at the same time");
            Environment.Exit(0);
        }
        if (!(arguments.EncryptMode || arguments.DecryptMode))
        {
            System.Console.WriteLine("Must specify mode to use (-e for encryption, or -u for unencryption)");
            Environment.Exit(0);
        }



        System.Console.WriteLine("Please input a Password for your File(s)");
        string pass = Console.ReadLine();
        Console.Clear();

        if (pass != null)
        {
            if (arguments.FileMode)
            {
                if (arguments.EncryptMode)
                {
                    FileLocker.FileLocker.EncryptFile(arguments.InputPath, pass, true);
                }
                else if (arguments.DecryptMode)
                {
                    FileLocker.FileLocker.DecryptFile(arguments.InputPath, pass, true);
                }
            }
            else if (arguments.DirMode)
            {
                if (arguments.EncryptMode)
                {
                    FileLocker.FileLocker.EncryptDir(arguments.InputPath, pass, true);
                }
                else if (arguments.DecryptMode)
                {
                    FileLocker.FileLocker.DecryptDir(arguments.InputPath, pass, true);
                }
            }
        }




    });
