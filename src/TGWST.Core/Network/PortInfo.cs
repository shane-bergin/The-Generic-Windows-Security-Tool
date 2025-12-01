namespace TGWST.Core.Network;

public sealed class PortInfo
{
    public int Port { get; }
    public string Protocol { get; }
    public string Address { get; }
    public int Pid { get; }
    public string ProcessName { get; }
    public string ServiceName { get; }

    public PortInfo(string address, int port, string protocol, int pid, string processName, string serviceName)
    {
        Address = address;
        Port = port;
        Protocol = protocol;
        Pid = pid;
        ProcessName = processName;
        ServiceName = serviceName;
    }

    public override string ToString() => $"{Protocol} {Address}:{Port} ({ProcessName})";
}
