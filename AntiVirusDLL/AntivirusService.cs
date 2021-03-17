using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiVirusDLL
{
    public class AntivirusService : IAntivirusService
    {
        private static DBContext context = new DBContext(@"/antivirus.db");
        private static ScannerFactory factory = new ScannerFactory(context);
        private static Queue<Task> tasks = new Queue<Task>();

        public List<Task> GetTasks()
        {
            return tasks.ToList<Task>();
        }

        public Task AddTask(string command)
        {

            Task task = new Task();
            tasks.Enqueue(task);

            return task;
        }

        

        public string Method1(string x)
        {
            string s = $"1 You entered: {x} = = = 1";
            return s;
        }

        public string Method2(string x)
        {
            string s = $"2 you entered: {x} = = = 2";
            return s;
        }
    }
}
