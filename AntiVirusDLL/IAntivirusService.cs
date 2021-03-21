using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.ServiceModel;

namespace AntiVirusDLL
{
    [ServiceContract]
    public interface IAntivirusService
    {
        [OperationContract]
        void Start();

        [OperationContract]
        List<Task> GetTasks();

        [OperationContract]
        List<Task> GetActiveTasks();

        [OperationContract]
        bool StopTask(Task task);

        [OperationContract]
        List<Virus> GetVirusesFound(Task task);

        [OperationContract]
        bool MoveToQuarantineVirus(Task task, Virus virus, bool MoveBack = false);

        [OperationContract]
        bool DeleteVirus(Task task, Virus virus);

        [OperationContract]
        bool AddNewTask(Task task);
    }
}
