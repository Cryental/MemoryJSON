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

            Console.WriteLine(trainer.Info.Author);
            trainer.Inject2Game();
            trainer.InitializeAoB();

            var generalTrainers = trainer.FindTab("General");
            Console.WriteLine(generalTrainers.SearchFunction("Infinity Sabotage").Enable());

            Console.ReadKey();
        }
    }
}
