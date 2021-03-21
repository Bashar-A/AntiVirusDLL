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
        public static int MAX_CONNECTIONS = 5;
        public static int CONNECTION_INSTANCES = 0;
        public DBContext()
        {
            //connection = new SqliteConnection("Data Source=" + source);
            //connection.Open();
        }

        private SqliteConnection GetConnection()
        {
            if(connections.Count > 0)
            {
                return connections.Dequeue();
            }
            else if(MAX_CONNECTIONS > CONNECTION_INSTANCES)
            {
                CONNECTION_INSTANCES++;
                return new SqliteConnection("Data Source=" + source);
            }
            else
            {
                while (true)
                {
                    if (connections.Count > 0)
                    {
                        return connections.Dequeue();
                    }
                }
            }
        }


        public List<VirusDataSet> GetViruses(string signature, int position)
        {
            List<VirusDataSet> viruses = new List<VirusDataSet>();
            SqliteConnection connection = new SqliteConnection("Data Source=" + source);
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
            return viruses;
        }
        public Task AddTask(Task task)
        {
            SqliteConnection connection = GetConnection();
            connection.Open();

            var command = connection.CreateCommand();
            command.CommandText = $"INSERT INTO tasks (type, option, isActive, path) VALUES ({task.Type}, {task.Option}, {task.IsActive}, {task.Path});SELECT CAST(scope_identity() AS int)";

            task.Id = (int)command.ExecuteScalar();

            connection.Close();
            connections.Enqueue(connection);
            return task;
        }
        public void UpdateTask(Task task)
        {
            SqliteConnection connection = GetConnection();
            connection.Open();

            var command = connection.CreateCommand();
            command.CommandText = $@"UPDATE tasks SET
                type = {task.Type}, 
                option = {task.Option}, 
                isActive = {task.IsActive},
                path = '{task.Path}',
                filesTotal = {task.FilesTotal},
                filesScanned = {task.FilesScanned},
                progress = {task.Progress} WHERE id = {task.Id}";
            command.ExecuteScalar();

            connection.Close();
            connections.Enqueue(connection);
        }
        public void AddVirusFound(Task task, Virus virus)
        {
            //TODO
            SqliteConnection connection = GetConnection();
            connection.Open();

            var command = connection.CreateCommand();
            command.CommandText = $"INSERT INTO viruses_found (taskId, path, name) VALUES ({task.Id}, {virus.Path}, {virus.Name})";

            command.ExecuteScalar();

            connection.Close();
            connections.Enqueue(connection);
        }
        public List<Task> GetTasks()
        {
            List<Task> tasks = new List<Task>();
            SqliteConnection connection = new SqliteConnection("Data Source=" + source);
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
                            Double.Parse(reader.GetString(7))
                        );
                    tasks.Add(task);
                }
            }

            connection.Close();
            return tasks;
        }
        public List<Task> GetActiveTasks()
        {
            List<Task> tasks = new List<Task>();
            SqliteConnection connection = new SqliteConnection("Data Source=" + source);
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
                            Double.Parse(reader.GetString(7))
                        );
                    tasks.Add(task);
                }
            }

            connection.Close();
            return tasks;
        }
        public List<Task> GetVirusesFound()
        {

            return null;
        }
        public List<Virus> GetVirusesFound(Task task)
        {
            List<Virus> viruses = new List<Virus>();
            SqliteConnection connection = new SqliteConnection("Data Source=" + source);
            connection.Open();
            var command = connection.CreateCommand();
            command.CommandText = $"SELECT path, name FROM tasks WHERE taskId = {task.Id}";
            using (var reader = command.ExecuteReader())
            {
                while (reader.Read())
                {
                    Virus virus = new Virus(reader.GetString(0), reader.GetString(1));
                    viruses.Add(virus);
                }
            }

            connection.Close();
            return viruses;
        }
    }
}
