using System;
using System.Collections.Generic;
using System.Threading;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiVirusDLL
{
    public class AntivirusService : IAntivirusService
    {
        private static DBContext context = new DBContext();
        //private static List<Scanner> scanners = new List<Scanner>();
        //private static List<Monitor> monitors = new List<Monitor>();
        private static List<Task> activeTasks = new List<Task>();
        private static List<Task> schedualedTasks = new List<Task>();
        private static Queue<Task> newTasks = new Queue<Task>();
        private static System.Timers.Timer aTimer;
        private static bool IsStarted = false;

        public void Start()
        {
            if (IsStarted) return;
            IsStarted = true;
            aTimer = new System.Timers.Timer();
            aTimer.Interval = 60000;
            aTimer.Elapsed += OnTimedEvent;
            aTimer.AutoReset = true;
            aTimer.Enabled = true;
            OnStart();

            Thread thread = new Thread(MonitorServiceTasks);
            thread.Start();
        }
        private void OnStart()
        {
            List<Task> tasks = context.GetActiveTasks();
            foreach(Task task in tasks)
            {
                if (task.Type == TaskType.SchedualScan) schedualedTasks.Add(task);
                else if (task.Type == TaskType.Monitor)
                {
                    Thread thread = new Thread(ActivateTask);
                    thread.Start(task);
                }
                else if (task.IsActive) task.IsActive = false;
            }
        }
        private void OnTimedEvent(Object source, System.Timers.ElapsedEventArgs e)
        {
            for (int i = schedualedTasks.Count - 1; i >= 0; i--)
            {
                if (schedualedTasks[i].Date.Minute < e.SignalTime.Minute)
                {
                    Task task = schedualedTasks[i];
                    schedualedTasks.RemoveAt(i);
                    task.Type = TaskType.Scan;
                    ActivateTask(task);
                    break;
                }
            }
            //Console.WriteLine("The Elapsed event was raised at {0}", e.SignalTime);
        }


        public List<Task> GetTasks()
        {
            return context.GetTasks();
        }
        public List<Task> GetActiveTasks()
        {
            return activeTasks;
        }
        public List<Virus> GetVirusesFound(Task task)
        {
            return context.GetVirusesFound(task);
        }
        public bool MoveToQuarantineVirus(Task task, Virus virus, bool MoveBack = false)
        {
            task = context.GetTaskById(task.Id);
            if(!Scanner.MoveToQuarantine(virus, MoveBack)) return false;
            task.UpdateVirus(virus);
            context.UpdateTask(task);
            virus.InQuarantine = !MoveBack;
            return context.UpdateVirusFound(virus);
        }
        public bool DeleteVirus(Task task, Virus virus)
        {
            task = context.GetTaskById(task.Id);
            if (!Scanner.DeleteVirus(virus)) return false;
            task.RemoveVirus(virus);
            context.UpdateTask(task);
            return context.DeleteVirusFound(virus);
        }
        public bool AddNewTask(Task task)
        {
            Console.WriteLine("Task added!");
            Console.WriteLine(task.Type);
            newTasks.Enqueue(task);

            return true;
        }
        public bool StopTask(Task task)
        {
            for (int i = activeTasks.Count - 1; i >= 0; i--)
            {
                if (activeTasks[i].Id == task.Id){
                    if (activeTasks[i].Type == TaskType.Monitor) context.UpdateTask(activeTasks[i]);
                    activeTasks[i].IsActive = false;
                    activeTasks.RemoveAt(i);
                    return true;
                }
            }

            for (int i = schedualedTasks.Count - 1; i >= 0; i--)
            {
                if (schedualedTasks[i].Id == task.Id)
                {
                    schedualedTasks[i].IsActive = false;
                    context.UpdateTask(schedualedTasks[i]);
                    schedualedTasks.RemoveAt(i);
                    return true;
                }
            }

            return false;
        }





        private void MonitorServiceTasks()
        {
            while (true)
            {
                if (newTasks.Count > 0)
                {
                    Thread thread = new Thread(ActivateNewTask);
                    thread.Start();
                }

                for (int i = activeTasks.Count - 1; i >= 0; i--)
                {
                    if (!activeTasks[i].IsActive) activeTasks.RemoveAt(i);
                }

                Thread.Sleep(1000);
            }
        }
        private void ActivateNewTask()
        {
            Task task;
            try
            {
                task = newTasks.Dequeue();
            }
            catch (Exception) { return; }
            activeTasks.Add(task);
            switch (task.Type)
            {
                case TaskType.Scan:
                    task = context.AddTask(task);
                    Scanner scanner = new Scanner(context, ref task);
                    //scanners.Add(scanner);
                    scanner.StartScanning();
                    break;
                case TaskType.Monitor:
                    task = context.AddTask(task);
                    Monitor monitor = new Monitor(context, ref task);
                    //monitors.Add(monitor);
                    monitor.StartScanning();
                    break;
                case TaskType.SchedualScan:
                    task = context.AddTask(task);
                    schedualedTasks.Add(task);
                    break;
                default:
                    break;
            }
        }
        private void ActivateTask(object data)
        {
            Task task = (Task)data;
            bool taskAlreadyAdded = false;
            foreach(var t in activeTasks)
            {
                if (t.Id == task.Id) taskAlreadyAdded = true;
            }
            if(!taskAlreadyAdded) activeTasks.Add(task);
            switch (task.Type)
            {
                case TaskType.Scan:
                    Scanner scanner = new Scanner(context, ref task);
                    //scanners.Add(scanner);
                    scanner.StartScanning();
                    break;
                case TaskType.Monitor:
                    Monitor monitor = new Monitor(context, ref task);
                    //monitors.Add(monitor);
                    monitor.StartScanning();
                    break;
                case TaskType.SchedualScan:
                    schedualedTasks.Add(task);
                    break;
                default:
                    break;
            }
        }

    }
}
