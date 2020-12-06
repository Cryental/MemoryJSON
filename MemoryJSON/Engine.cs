using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MemoryJSON
{
    public class Engine
    {
        public Trainer CreateTrainerFromFile(string filePath)
        {
            var readFile = File.ReadAllText(filePath);

            if (!AmberJSON.Helpers.IsValidJson(readFile))
            {
                throw new Exception("The imported file is corrupted or not supported file.");
            }

            return new Trainer(readFile);
        }
    }
}
