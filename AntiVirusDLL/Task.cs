using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiVirusDLL
{
    public class Task
    {
        public Task(TaskType type, bool isActive, string path,  TaskOption option = TaskOption.Nothing)
        {
            Type = type;
            Option = option;
            IsActive = isActive;
            Path = path;
            FilesTotal = 0;
            FilesScanned = 0;
            Progress = 0;
        }


        public Task()
        {
        }

        public Task(int id, TaskType type, TaskOption option, bool isActive, string path, int filesTotal, int filesScanned, double progress)
        {
            Id = id;
            Type = type;
            Option = option;
            IsActive = isActive;
            Path = path;
            FilesTotal = filesTotal;
            FilesScanned = filesScanned;
            Progress = progress;
        }

        public List<Virus> VirusFound = new List<Virus> ();
        public int Id { get; set; }
        public TaskType Type { get; set; }
        public TaskOption Option { get; set; }
        public bool IsActive { get; set; }
        public string Path { get; set; }
        public int FilesTotal { get; set; }
        public int FilesScanned { get; set; }
        public double Progress { get; set; }

    }
    public class Virus
    {
        public Virus(string path, string name)
        {
            Path = path;
            Name = name;
        }


        public string Path { get; set; }
        public string Name { get; set; }
    }


    public enum TaskType
    {
        Scan,
        Monitor,
        SchedualScan
    }
    public enum TaskOption
    {
        Nothing,
        Quarntine,
        Delete
    }
}