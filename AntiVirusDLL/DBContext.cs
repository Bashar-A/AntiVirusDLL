using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;

namespace AntiVirusDLL
{
    public class DBContext
    {
        Queue<SqliteConnection> connections = new Queue<SqliteConnection>();
        public static string source = @"D:\AntivirusDB.db";
        //public static int MAX_CONNECTIONS = 20;
        //public static int CONNECTION_INSTANCES = 0;

        private SqliteConnection GetConnection()
        {
            return new SqliteConnection("Data Source=" + source);
            //if (connections.Count > 0)
            //{
            //    return connections.Dequeue();
            //}
            //else if(MAX_CONNECTIONS > CONNECTION_INSTANCES)
            //{
            //    CONNECTION_INSTANCES++;
            //    return new SqliteConnection("Data Source=" + source);
            //}
            //else
            //{
            //    while (true)
            //    {
            //        if (connections.Count > 0)
            //        {
            //            return connections.Dequeue();
            //        }
            //    }
            //}
        }


        public List<VirusDataSet> GetViruses(string signature, int position)
        {
            List<VirusDataSet> viruses = new List<VirusDataSet>();
            SqliteConnection connection = GetConnection();
            connection.Open();
            var command = connection.CreateCommand();
            command.CommandText = $"SELECT * FROM viruses WHERE Signature Like '{signature}%' AND OffsetBegin <= {position} AND OffsetEnd >= {position}";
            using (var reader = command.ExecuteReader())
            {
                while (reader.Read())
                {
                    VirusDataSet virus = new VirusDataSet(
                            Int32.Parse(reader.GetString(0)),
                            reader.GetString(1),
                            reader.GetString(2),
                            Int32.Parse(reader.GetString(3)),
                            Int32.Parse(reader.GetString(4))
                        );
                    viruses.Add(virus);

                }
            }
            
            connection.Close();
            //connections.Enqueue(connection);
            return viruses;
        }
        public Task GetTaskById(int id)
        {
            Task task = new Task();
            SqliteConnection connection = GetConnection();
            connection.Open();
            var command = connection.CreateCommand();
            command.CommandText = $"SELECT * FROM tasks WHERE id = {id}";
            using (var reader = command.ExecuteReader())
            {
                while (reader.Read())
                {
                    task = new Task(
                            Int32.Parse(reader.GetString(0)),
                            (TaskType)Int32.Parse(reader.GetString(1)),
                            (TaskOption)Int32.Parse(reader.GetString(2)),
                            reader.GetString(3) == "1",
                            reader.GetString(4),
                            Int32.Parse(reader.GetString(5)),
                            Int32.Parse(reader.GetString(6)),
                            Double.Parse(reader.GetString(7)),
                            new DateTime(Int64.Parse(reader.GetString(8)))
                        );
                }
            }

            connection.Close();
            //connections.Enqueue(connection);
            return task;
        }
        public Task AddTask(Task task)
        {
            SqliteConnection connection = GetConnection();
            connection.Open();

            var command = connection.CreateCommand();
            command.CommandText = $"INSERT INTO tasks (type, option, isActive, path, dateTime) VALUES ({(int)task.Type}, {(int)task.Option}, {task.IsActive}, '{task.Path}', {task.Date.Ticks})";
            command.ExecuteScalar();
            command.CommandText = "select last_insert_rowid()";
            Int64 LastRowID64 = (Int64)command.ExecuteScalar();
            task.Id = (int)LastRowID64;

            connection.Close();
            connections.Enqueue(connection);
            return task;
        }
        public void UpdateTask(Task task)
        {
            SqliteConnection connection = GetConnection();
            connection.Open();

            var command = connection.CreateCommand();
            command.CommandText = $@"UPDATE tasks SET type = {(int)task.Type}, option = {(int)task.Option}, isActive = {task.IsActive},
                path = '{task.Path}',
                filesTotal = {task.FilesTotal},
                filesScanned = {task.FilesScanned},
                progress = '{task.Progress}' WHERE id = {task.Id}";
            command.ExecuteScalar();
            

            connection.Close();
            //connections.Enqueue(connection);
        }
        public bool DeleteTask(Task task)
        {
            SqliteConnection connection = GetConnection();
            connection.Open();
            try
            {
                var command = connection.CreateCommand();
                command.CommandText = $@"DELETE FROM tasks WHERE id = '{task.Id}'";
                command.ExecuteScalar();
            }
            catch (Exception) { connection.Close(); return false; }

            connection.Close();
            return true;
            //connections.Enqueue(connection)
        }
        public bool AddVirusFound(Task task, Virus virus)
        {
            //TODO
            SqliteConnection connection = GetConnection();
            connection.Open();

            var command = connection.CreateCommand();
            try
            {
                command.CommandText = $"INSERT INTO viruses_found (taskId, path, name, inQuarantine) VALUES ({task.Id}, '{virus.Path}', '{virus.Name}', {virus.InQuarantine})";

                command.ExecuteScalar();

            }
            catch (Exception) { connection.Close(); return false; }
            connection.Close();
            return true;
            //connections.Enqueue(connection);
        }
        public bool UpdateVirusFound(Virus virus)
        {
            SqliteConnection connection = GetConnection();
            connection.Open();

            try
            {
                var command = connection.CreateCommand();
                command.CommandText = $@"UPDATE viruses_found SET inQuarantine = {virus.InQuarantine} WHERE path = '{virus.Path}'";
                command.ExecuteScalar();
            }
            catch (Exception) { connection.Close(); return false; }

            connection.Close();
            return true;
            //connections.Enqueue(connection)
        }
        public bool DeleteVirusFound(Virus virus)
        {
            SqliteConnection connection = GetConnection();
            connection.Open();
            try
            {
                var command = connection.CreateCommand();
                command.CommandText = $@"DELETE FROM viruses_found WHERE path = '{virus.Path}'";
                command.ExecuteScalar();
            }
            catch (Exception) { connection.Close(); return false; }

            connection.Close();
            return true;
            //connections.Enqueue(connection)
        }
        public List<Task> GetTasks()
        {
            List<Task> tasks = new List<Task>();
            SqliteConnection connection = GetConnection();
            connection.Open();
            var command = connection.CreateCommand();
            command.CommandText = $"SELECT * FROM tasks";
            using (var reader = command.ExecuteReader())
            {
                while (reader.Read())
                {
                    Task task = new Task(
                            Int32.Parse(reader.GetString(0)),
                            (TaskType)Int32.Parse(reader.GetString(1)),
                            (TaskOption)Int32.Parse(reader.GetString(2)),
                            reader.GetString(3) == "1",
                            reader.GetString(4),
                            Int32.Parse(reader.GetString(5)),
                            Int32.Parse(reader.GetString(6)),
                            Double.Parse(reader.GetString(7)),
                            new DateTime(Int64.Parse(reader.GetString(8)))
                        );
                    tasks.Add(task);
                }
            }

            connection.Close();
            //connections.Enqueue(connection);
            return tasks;
        }
        public List<Task> GetActiveTasks()
        {
            List<Task> tasks = new List<Task>();
            SqliteConnection connection = GetConnection();
            connection.Open();
            var command = connection.CreateCommand();
            command.CommandText = $"SELECT * FROM tasks WHERE isActive = {1}";
            using (var reader = command.ExecuteReader())
            {
                while (reader.Read())
                {
                    Task task = new Task(
                            Int32.Parse(reader.GetString(0)),
                            (TaskType)Int32.Parse(reader.GetString(1)),
                            (TaskOption)Int32.Parse(reader.GetString(2)),
                            reader.GetString(3) == "1",
                            reader.GetString(4),
                            Int32.Parse(reader.GetString(5)),
                            Int32.Parse(reader.GetString(6)),
                            Double.Parse(reader.GetString(7)),
                            new DateTime(Int64.Parse(reader.GetString(8)))
                        );
                    tasks.Add(task);
                }
            }

            connection.Close();
            //connections.Enqueue(connection);
            return tasks;
        }
        public List<Virus> GetVirusesFound(Task task)
        {
            List<Virus> viruses = new List<Virus>();
            SqliteConnection connection = GetConnection();
            connection.Open();
            var command = connection.CreateCommand();
            command.CommandText = $"SELECT path, name, inQuarantine FROM viruses_found WHERE taskId = {task.Id}";
            using (var reader = command.ExecuteReader())
            {
                while (reader.Read())
                {
                    Virus virus = new Virus(reader.GetString(0), reader.GetString(1), reader.GetString(2) == "1");
                    viruses.Add(virus);
                }
            }

            connection.Close();
            //connections.Enqueue(connection);
            return viruses;
        }
    }
}
