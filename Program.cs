using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;

namespace detectDebugger
{
    class Program
    {
        static void AntiReverse()
        {
            while(true)
            {
                CAntiReverse.Run();
                Thread.Sleep(1);
            }
        }

        static void Main(string[] args)
        {
            Thread tAntiReverse = new Thread(new ThreadStart(AntiReverse));
            tAntiReverse.Start();
        }
    }
}
