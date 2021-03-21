using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Threading;

namespace AntiVirusDLL
{
    public class Monitor : Scanner
    {
        static List<FileSystemWatcher> MonitoredDirectories = new List<FileSystemWatcher>();

        public Monitor(DBContext dBContext, ref Task task) : base(dBContext, ref task)
        {
        }

        override public void StartScanning()
        {
            //Scanning directories
            IsScanning = true;
            Thread thread1 = new Thread(ScanFiles);
            Thread thread2 = new Thread(ScanZipFiles);
            thread1.Start();
            thread2.Start();
        }

        
        public bool RemoveDir(string path)
        {
            for (int i = MonitoredDirectories.Count - 1; i > 0; i--)
            {
                if (MonitoredDirectories[i].Path.Equals(path))
                {
                    MonitoredDirectories[i].Dispose();
                    MonitoredDirectories.RemoveAt(i);
                    task.IsActive = false;
                    return true;
                }
            }
            return false;
        }
        public bool CheckSubDirPath(string path)
        {
            foreach(FileSystemWatcher watcher in MonitoredDirectories)
            {
                if (path.IndexOf(watcher.Path) > 0) return false;
            }

            return true;
        }
        public bool MonitorDir(string path)
        {
            if (CheckSubDirPath(path)) return false;
            FileSystemWatcher watcher = new FileSystemWatcher(path);
            MonitoredDirectories.Add(watcher);
            watcher.NotifyFilter = NotifyFilters.LastWrite;
            watcher.Filter = "*";
            watcher.IncludeSubdirectories = true;
            watcher.EnableRaisingEvents = true;

            watcher.Changed += OnChanged;

            return true;
            //Console.WriteLine($"Monitoring: {path}");

        }
        private void OnChanged(object sender, FileSystemEventArgs e)
        {
            if (File.GetAttributes(e.FullPath).HasFlag(FileAttributes.Directory)) return;
            FilesToBeScanned.Enqueue(e.FullPath);
            if (!IsScanning) StartScanning();
            Console.WriteLine($"Changed: {e.FullPath}, Type: {e.ChangeType}");
        }
    }
}
