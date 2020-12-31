using System;
using System.IO;
using MemoryJSON.AmberJSON;

namespace MemoryJSON
{
    public class Engine
    {
        public Trainer CreateTrainerFromFile(string filePath)
        {
            var readFile = File.ReadAllText(filePath);

            if (!Helpers.IsValidJson(readFile))
                throw new Exception("The imported file is corrupted or not supported file.");

            return new Trainer(readFile);
        }

        public Trainer CreateTrainerFromFile(string filePath, string password)
        {
            var readFile = File.ReadAllBytes(filePath);

            var decryptedFile = Encryption.Decrypt(readFile, password);

            if (decryptedFile == "ERROR_501622")
                throw new Exception("The password you entered is invalid or incorrect.");

            if (!Helpers.IsValidJson(decryptedFile))
                throw new Exception("The imported file is corrupted or not supported file.");

            return new Trainer(decryptedFile);
        }

        public void EncryptFile(string sourceFilePath, string descFilePath, string password)
        {
            var readFile = File.ReadAllText(sourceFilePath);

            try
            {
                var encryptedFile = Encryption.Encrypt(readFile, password);

                File.WriteAllBytes(descFilePath, encryptedFile);
            }
            catch
            {
                throw new Exception("There was a problem while encrypting the file.");
            }
        }
    }
}