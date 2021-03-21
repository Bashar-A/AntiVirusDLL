﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.IO.Compression;
using System.Threading;
using System.Runtime;

namespace AntiVirusDLL
{
    public class Scanner
    {
        public static DBContext context;
        public Queue<string> FilesToBeScanned = new Queue<string>();
        protected Queue<string> DirectoriesToBeScanned = new Queue<string>();
        protected Queue<string> ArchivesToCheck = new Queue<string>();
        public Task task;
        protected bool IsScanning;

        public Scanner(DBContext dBContext, ref Task task)
        {
            context = dBContext;
            this.task = task;
        }

        public virtual void StartScanning()
        {
            //Scanning directories
            IsScanning = true;
            if (File.GetAttributes(task.Path).HasFlag(FileAttributes.Directory)) ScanDir(task.Path);
            else FilesToBeScanned.Enqueue(task.Path);



            Thread thread1 = new Thread(ScanFiles);
            Thread thread2 = new Thread(ScanZipFiles);
            thread1.Start();
            thread2.Start();

            while (IsScanning && task.IsActive)
            {
                task.FilesScanned = task.FilesTotal - FilesToBeScanned.Count;
                task.Progress = task.FilesScanned / task.FilesTotal;
                Thread.Sleep(100);
            }

            task.IsActive = false;
        }

        protected void ScanZipFiles()
        {
            while (FilesToBeScanned.Count > 0 && task.IsActive)
            {
                if (ArchivesToCheck.Count > 0)
                {
                    string path = ArchivesToCheck.Dequeue();
                    ScanZipFileStream(GetFileStream(path), path);
                }
            }
            IsScanning = false;
        }
        protected void ScanFiles()
        {
            while (FilesToBeScanned.Count > 0 && task.IsActive)
            {
                string path = FilesToBeScanned.Dequeue();

                //если файл оказался исполняемым, то мы мы проверяем его сигнатуру
                if(ScanFileStream(GetFileStream(path), path)) CheckFileStream(GetFileStream(path), path);
            }
            //IsScanning = false;
        }



        protected void ScanDir(string path)
        {
            Console.WriteLine("Scanning dir: " + path);
            string[] allFiles = Directory.GetFiles(path, "*");
            string[] allDirectories = Directory.GetDirectories(path, "*");

            foreach (string dir in allDirectories)
            {
                DirectoriesToBeScanned.Enqueue(dir);
            }

            task.FilesTotal += allFiles.Length;
            foreach (string file in allFiles)
            {
                FilesToBeScanned.Enqueue(file);
            }

            if (DirectoriesToBeScanned.Count > 0) ScanDir(DirectoriesToBeScanned.Dequeue());

        }
        protected Stream GetFileStream(string path)
        {
            while (true)
            {
                try
                {
                    FileStream stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
                    return stream;
                }
                catch (IOException)
                {
                    Thread.Sleep(100);
                }
            }
        }
        protected bool ScanFileStream(Stream file, string path, bool fromArchive = false)
        {
            bool result = false;
            switch ((char)file.ReadByte())
            {
                case 'M': //MZ
                    if ((char)file.ReadByte() == 'Z')
                    {
                        if (fromArchive) CheckFileStream(file, path);
                        Console.WriteLine("Found exe: " + path);
                        result = true;
                    }
                    break;
                case '.': //.ELF
                    if ((char)file.ReadByte() == 'E' &&
                        (char)file.ReadByte() == 'L' &&
                        (char)file.ReadByte() == 'F')
                    {
                        if (fromArchive) CheckFileStream(file, path);
                        result = true;
                    }
                    break;
                case 'P': //PK
                    if ((char)file.ReadByte() == 'K')
                    {
                        Console.WriteLine("Zip file found at: " + path);
                        Console.WriteLine("From Archive: " + fromArchive);
                        if (fromArchive) ScanZipFileStream(file, path);
                        else ArchivesToCheck.Enqueue(path);
                    }
                    break;
                default:
                    break;
            }
            file.Close();
            return result;
        }
        protected virtual void CheckFileStream(Stream stream, string path)
        {
            int offset = 0;
            bool malwareFound = false;
            byte[] data = GetFileCode(stream, ref offset);
            for (int i = 0; i < data.Length - 4 && !malwareFound; i++)
            {
                string sign = GetStringOfBytes(data, i, 4);
                List<VirusDataSet> viruses = context.GetViruses(sign, offset + i);
                foreach (VirusDataSet virus in viruses)
                {
                    if (CheckSignatureFullMatch(virus, data, i))
                    {
                        task.VirusFound.Add(new Virus(path, virus.Name));
                        Console.WriteLine($"Malware found!! at: {path} | name: {virus.Name} ");
                        Console.WriteLine($"Malware Signature: {virus.Signature}");
                        malwareFound = true;
                        break;
                    }
                }
            }

            if (malwareFound) switch (task.Option)
                {
                    case TaskOption.Quarntine:
                        MoveToQuarantine(path);
                        break;
                    case TaskOption.Delete:
                        DeleteFile(path);
                        break;
                    default:
                        break;
                }
        }
        protected bool CheckSignatureFullMatch(VirusDataSet virus, byte[] data, int offset)
        {
            string signature = GetStringOfBytes(data, offset, virus.Signature.Length / 2);
            //TODO && offset + virus.Signature.Length < virus.OffsetEnd
            if (signature.Equals(virus.Signature) && offset + virus.Signature.Length < virus.OffsetEnd) return true;
            return false;
        }
        protected string GetStringOfBytes(byte[] array, int index, int length)
        {
            return BitConverter.ToString(array, index, length).Replace("-", "");
        }
        protected byte[] GetFileCode(Stream stream, ref int offset)
        {
            //.text МОЖЕТ НЕ БЫТЬ
            bool txtIsFound = false;
            while (!txtIsFound)
            {
                switch ((char)stream.ReadByte())
                {
                    case '.': //.text
                        if ((char)stream.ReadByte() == 't' &&
                            (char)stream.ReadByte() == 'e' &&
                            (char)stream.ReadByte() == 'x' &&
                            (char)stream.ReadByte() == 't') txtIsFound = true;
                        break;
                    default:
                        break;
                }
            }
            stream.Position += 10;

            byte[] array = new byte[4];
            stream.Read(array, 0, 4);
            Array.Reverse(array, 0, array.Length);
            int rawDataSize = BitConverter.ToInt32(array, 0);
            Console.WriteLine("rawDataSize = " + rawDataSize);

            stream.Read(array, 0, 4);
            Array.Reverse(array, 0, array.Length);
            int rawDataPosition = BitConverter.ToInt32(array, 0);
            Console.WriteLine("rawDataPosition = " + rawDataPosition);

            offset = rawDataPosition;
            array = new byte[rawDataSize];
            stream.Position = rawDataPosition;
            stream.Read(array, 0, rawDataSize - 1);
            //Console.WriteLine("rawData: " + BitConverter.ToString(array));

            stream.Close();

            return array;
        }
        protected void ScanZipFileStream(Stream stream, string path)
        {
            //stream.Position = 0;
            //stream.Seek(0, SeekOrigin.Begin);
            //stream.flush()
            Console.WriteLine("Try to scan zip file stream: " + path);
            stream.Close();
            return;
            try
            {
                using (ZipArchive archive = new ZipArchive(stream))
                {
                    foreach (ZipArchiveEntry entry in archive.Entries)
                    {
                        using (Stream reader = entry.Open())
                        {
                            ScanFileStream(reader, path, true);
                        }
                    }
                }
            }
            catch (Exception e) { }
        }


        //TODO
        protected void MoveToQuarantine(string path)
        {

        }
        protected void DeleteFile(string path)
        {

        }
    }
}
