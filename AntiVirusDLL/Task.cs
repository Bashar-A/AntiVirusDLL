using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiVirusDLL
{
    public class Task
    {
        public Task(TaskType type, bool isActive,  string path, uint handler, TaskOption option = TaskOption.Nothing)
        {
            Type = type;
            Option = option;
            IsActive = isActive;
            Path = path;
            Handler = handler;
            FilesTotal = 0;
            FilesScanned = 0;
            Progress = 0;
        }
        public Dictionary<string, string> MalwareFound = new Dictionary<string, string>();
        public TaskType Type { get; set; }
        public TaskOption Option { get; set; }
        public bool IsActive { get; set; }
        public string Path { get; set; }
        public uint Handler { get; private set; }
        public int FilesTotal { get; set; }
        public int FilesScanned { get; set; }
        public double Progress { get; set; }

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