using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiVirusDLL
{
    public class VirusDataSet
    {
        public VirusDataSet(int id, string name, string signature, int offsetBegin, int offsetEnd)
        {
            Id = id;
            Name = name;
            Signature = signature;
            OffsetBegin = offsetBegin;
            OffsetEnd = offsetEnd;
        }

        public int Id { get; set; }
        public string Name { get; set; }
        public string Signature { get; set; }
        public int OffsetBegin { get; set; }
        public int OffsetEnd { get; set; }

    }
}
