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
        public Monitor(DBContext dBContext, ref Task task) : base(dBContext, ref task)
        {
        }

        override public void StartScanning()
        {
            //Scanning directories
            MonitorDir(task.Path);
            IsScanning = true;
            Thread thread1 = new Thread(ScanFiles);
            Thread thread2 = new Thread(ScanZipFiles);
            thread1.Start();
            thread2.Start();
        }

        override protected void ScanZipFiles()
        {
            while (task.IsActive)
            {
                if (ArchivesToCheck.Count > 0)
                {
                    string path = ArchivesToCheck.Dequeue();
                    ScanZipFileStream(GetFileStream(path), path);
                }
                else Thread.Sleep(1000);
            }
            IsScanning = false;
        }
        override protected void ScanFiles()
        {
            while (task.IsActive)
            {
                if (FilesToBeScanned.Count > 0)
                {
                    string path = FilesToBeScanned.Dequeue();

                    //если файл оказался исполняемым, то мы мы проверяем его сигнатуру
                    if (ScanFileStream(GetFileStream(path), path))
                    {
                        CheckFileStream(GetFileStream(path), path);
                    }
                }
                else Thread.Sleep(1000);
            }
            //IsScanning = false;
        }

        public bool MonitorDir(string path)
        {
            //if (CheckSubDirPath(path)) return false;
            FileSystemWatcher watcher = new FileSystemWatcher(path);
            //MonitoredDirectories.Add(watcher);
            watcher.NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size;
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
            List <string> files = FilesToBeScanned.ToList();
            foreach (var item in files)
            {
                if (item.Equals(e.FullPath)) return;
            }
            FilesToBeScanned.Enqueue(e.FullPath);
            if (!IsScanning)
            {
                IsScanning = true;
                Thread thread1 = new Thread(ScanFiles);
                Thread thread2 = new Thread(ScanZipFiles);
                thread1.Start();
                thread2.Start();
            }
            Console.WriteLine($"Changed: {e.FullPath}, Type: {e.ChangeType}");
        }
    }
}
