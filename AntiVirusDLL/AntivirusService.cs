using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiVirusDLL
{
    public class AntivirusService : IAntivirusService
    {
        private static DBContext context = new DBContext();
        private static List<Scanner> scanners = new List<Scanner>();
        private static List<Monitor> monitors = new List<Monitor>();
        private static List<Task> tasks = new List<Task>();

        public List<Task> GetTasks()
        {
            return context.GetTasks();
        }

        public Task AddTask(string command)
        {

            Task task = new Task();
            tasks.Add(task);

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
