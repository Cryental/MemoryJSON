using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MemoryJSON.Test
{
    class Program
    {
        static void Main(string[] args)
        {
            var memoryengine = new MemoryJSON.Engine();
                
            var trainer = memoryengine.CreateTrainerFromFile("among us.amber");

            Console.WriteLine(trainer.Inject2Game());
            Console.WriteLine(trainer.Info.Name);
            Console.ReadKey();
        }
    }
}
