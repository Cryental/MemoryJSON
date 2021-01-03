using System;
using System.IO;
using System.Net;
using MemoryJSON;

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

            if (!Helpers.IsValidJson(readFile))
                throw new Exception("The imported file is corrupted or not supported file.");

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

        public Trainer CreateTrainerFromURL(string url)
        {
            try
            {
                var loadedFile = new WebClient {Proxy = new WebProxy()}.DownloadString(url);

                if (!Helpers.IsValidJson(loadedFile))
                    throw new Exception("The imported file is corrupted or not supported file.");

                return new Trainer(loadedFile);
            }
            catch
            {
                throw new Exception("There was a problem while loading the file from the internet.");
            }
        }

        public Trainer CreateTrainerFromURL(string url, string password)
        {
            try
            {
                var loadedFile = new WebClient {Proxy = new WebProxy()}.DownloadData(url);

                var decryptedFile = Encryption.Decrypt(loadedFile, password);

                if (decryptedFile == "ERROR_501622")
                    throw new Exception("The password you entered is invalid or incorrect.");

                if (!Helpers.IsValidJson(decryptedFile))
                    throw new Exception("The imported file is corrupted or not supported file.");

                return new Trainer(decryptedFile);
            }
            catch
            {
                throw new Exception("There was a problem while loading the file from the internet.");
            }
        }

        public Trainer CreateTrainerFromURL(string url, string webUsername, string webPassword)
        {
            try
            {
                var loadedFile = new WebClient
                        {Proxy = new WebProxy(), Credentials = new NetworkCredential(webUsername, webPassword)}
                    .DownloadString(url);

                if (!Helpers.IsValidJson(loadedFile))
                    throw new Exception("The imported file is corrupted or not supported file.");

                return new Trainer(loadedFile);
            }
            catch
            {
                throw new Exception("There was a problem while loading the file from the internet.");
            }
        }

        public Trainer CreateTrainerFromURL(string url, string password, string webUsername, string webPassword)
        {
            try
            {
                var loadedFile = new WebClient
                        {Proxy = new WebProxy(), Credentials = new NetworkCredential(webUsername, webPassword)}
                    .DownloadData(url);

                var decryptedFile = Encryption.Decrypt(loadedFile, password);

                if (!Helpers.IsValidJson(decryptedFile))
                    throw new Exception("The imported file is corrupted or not supported file.");

                return new Trainer(decryptedFile);
            }
            catch
            {
                throw new Exception("There was a problem while loading the file from the internet.");
            }
        }
    }
}