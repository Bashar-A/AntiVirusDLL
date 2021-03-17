using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiVirusDLL
{
    class ScannerFactory
    {
        private static int PoolMaxSize = 5;
        private static DBContext context;
        private static readonly Queue<Scanner> ScannerPool = new Queue<Scanner>(PoolMaxSize);

        public ScannerFactory(DBContext dBContext)
        {
            context = dBContext;
        }

        public Scanner GetScanner()
        {
            Scanner Scanner;
            if (Scanner.ObjectCounter >= PoolMaxSize && ScannerPool.Count > 0)
            {
                Scanner = RetrieveFromPool();
            }
            else
            {
                Scanner = GetNewScanner();
            }
            return Scanner;
        }
        private Scanner GetNewScanner()
        {
            Scanner Scanner = new Scanner(context, new Task());
            ScannerPool.Enqueue(Scanner);
            return Scanner;
        }
        protected Scanner RetrieveFromPool()
        {
            Scanner Scanner;
            if (ScannerPool.Count > 0)
            {
                Scanner = ScannerPool.Dequeue();
                Scanner.ObjectCounter--;
            }
            else
            {
                Scanner = new Scanner(context, new Task());
            }
            return Scanner;
        }
    }
}
