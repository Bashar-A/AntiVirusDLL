using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace AntiVirusDLL
{
    class Monitor : Scanner
    {
        static List<FileSystemWatcher> MonitoredDirectories = new List<FileSystemWatcher>();
        protected bool IsMonitoring;
        public Monitor(DBContext dBContext)
        {
            context = dBContext;
        }

        public void RemoveDir(string path)
        {
            for (int i = MonitoredDirectories.Count - 1; i > 0; i--)
            {
                if (MonitoredDirectories[i].Path.Equals(path))
                {
                    MonitoredDirectories[i].Dispose();
                    MonitoredDirectories.RemoveAt(i);
                    break;
                }
            }
        }

        public bool CheckSubDirPath(string path)
        {
            foreach(FileSystemWatcher watcher in MonitoredDirectories)
            {
                if (path.IndexOf(watcher.Path) > 0) return false;
            }

            return true;
        }
        public void MonitorDir(object data)
        {
            string path = data.ToString();
            if (CheckSubDirPath(path)) return;
            IsMonitoring = true;
            FileSystemWatcher watcher = new FileSystemWatcher(path);
            MonitoredDirectories.Add(watcher);
            watcher.NotifyFilter = NotifyFilters.Attributes;

            watcher.Changed += OnChanged;
            

            watcher.Filter = "*";
            watcher.IncludeSubdirectories = true;
            watcher.EnableRaisingEvents = true;
            Console.WriteLine($"Monitoring: {path}");

        }

        private void OnChanged(object sender, FileSystemEventArgs e)
        {
            IsScanning = true;
            Scan(e.FullPath);
            Console.WriteLine($"Changed: {e.FullPath}, Type: {e.ChangeType}");
        }
    }
}
