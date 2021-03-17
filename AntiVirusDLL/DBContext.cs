using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;

namespace AntiVirusDLL
{
    class DBContext
    {
        SqliteConnection connection;

        public DBContext(String source)
        {
            connection = new SqliteConnection("Data Source=" + source);
            connection.Open();
        }

        public List<VirusDTO> GetViruses(string signature, int position)
        {
            List<VirusDTO> viruses = new List<VirusDTO>();
            var command = connection.CreateCommand();
            command.CommandText = $"SELECT * FROM viruses WHERE Signature Like '{signature}%' AND OffsetBegin <= {position} AND OffsetEnd >= {position}";
            using (var reader = command.ExecuteReader())
            {
                while (reader.Read())
                {
                    VirusDTO virus = new VirusDTO(
                            Int32.Parse(reader.GetString(0)),
                            reader.GetString(1),
                            reader.GetString(2),
                            Int32.Parse(reader.GetString(3)),
                            Int32.Parse(reader.GetString(4))
                        );
                    viruses.Add(virus);

                }
            }

            return viruses;
        }
    }
}
