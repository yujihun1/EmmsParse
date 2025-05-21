using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;
using System;
using System.Data.SQLite;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

class Program
{
    static object consoleLock = new object();
    static int packetCount = 0;
    static CancellationTokenSource cts = new CancellationTokenSource();

    static async Task Main()
    {
        Console.WriteLine("패킷 캡처 프로그램 시작...");
        Console.WriteLine($"SharpPcap 버전: {SharpPcap.Version.VersionString}");

        var devices = LibPcapLiveDeviceList.Instance;

        if (devices.Count < 1)
        {
            Console.WriteLine("사용 가능한 네트워크 어댑터가 없습니다.");
            Console.WriteLine("Npcap 또는 WinPcap이 설치되어 있는지 확인하세요.");
            WaitForKeyPress();
            return;
        }

        // 어댑터 목록 표시
        Console.WriteLine("\n사용 가능한 네트워크 어댑터 목록:");
        Console.WriteLine("----------------------------------------");
        for (int i = 0; i < devices.Count; i++)
        {
            var dev = devices[i];
            string guid = ExtractGuid(dev.Name);
            Console.WriteLine($"{i}: {dev.Description} [{guid}]");

            foreach (var addr in dev.Addresses)
            {
                if (addr.Addr?.ipAddress != null)
                {
                    Console.WriteLine($"   IP: {addr.Addr.ipAddress}");
                }
            }
        }

        Console.WriteLine("----------------------------------------");
        Console.Write("사용할 어댑터 번호를 입력하세요: ");
        int selectedIndex;
        while (!int.TryParse(Console.ReadLine(), out selectedIndex) ||
               selectedIndex < 0 || selectedIndex >= devices.Count)
        {
            Console.Write("올바른 어댑터 번호를 입력하세요: ");
        }

        var selectedDevice = devices[selectedIndex] as LibPcapLiveDevice;
        Console.WriteLine($"\n선택한 어댑터: {selectedDevice.Description}");

        try
        {
            string filter = "tcp or udp";
            selectedDevice.Open(DeviceMode.Normal, 1000);
            selectedDevice.Filter = filter;
            Console.WriteLine($"필터가 설정되었습니다: {filter}");

            selectedDevice.OnPacketArrival += (sender, e) =>
            {
                var packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
                var ipv4 = packet.Extract<IPv4Packet>();
                var ipv6 = packet.Extract<IPv6Packet>();

                if (ipv4 != null)
                    ProcessIPPacket(ipv4, e.Packet.Timeval.Date);
                else if (ipv6 != null)
                    ProcessIPPacket(ipv6, e.Packet.Timeval.Date);
            };

            try
            {
                SaveToSQLite(selectedDevice.Name);
            }
            catch (Exception ex)
            {
                Console.WriteLine("설정 저장 중 오류: " + ex.Message);
            }

            // Ctrl+C 처리
            Console.CancelKeyPress += (s, e) =>
            {
                e.Cancel = true;
                Console.WriteLine("\nCtrl+C 감지됨. 캡처 중지 중...");
                cts.Cancel();
            };

            Console.WriteLine("\n패킷 캡처를 시작합니다. 중지하려면 Ctrl + C를 누르세요.");

            Task captureTask = Task.Run(() =>
            {
                try
                {
                    selectedDevice.StartCapture();
                    while (!cts.Token.IsCancellationRequested)
                        Thread.Sleep(500);
                    selectedDevice.StopCapture();
                    selectedDevice.Close();
                    lock (consoleLock)
                    {
                        Console.WriteLine("캡처가 중지되었습니다.");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("캡처 오류: " + ex.Message);
                }
            }, cts.Token);

            // @ 표시 Task (다른 비동기 작업 시뮬레이션)
            Task printerTask = Task.Run(async () =>
            {
                while (!cts.Token.IsCancellationRequested)
                {
                    await Task.Delay(2000);
                    lock (consoleLock)
                    {
                        Console.WriteLine("@@@@@@@@@@@@@@@@ [알림 Task] @@@@@@@@@@@@@@@@");
                    }
                }
            }, cts.Token);

            await Task.WhenAll(captureTask, printerTask);
        }
        catch (Exception ex)
        {
            Console.WriteLine("어댑터 열기 실패: " + ex.Message);
            Console.WriteLine("\n문제 해결 방법:");
            Console.WriteLine("1. 관리자 권한으로 실행");
            Console.WriteLine("2. Npcap 설치 확인: https://npcap.com");
            Console.WriteLine("3. 다른 어댑터 선택");
            Console.WriteLine("4. 방화벽 설정 확인");
            WaitForKeyPress();
        }
    }

    static void ProcessIPPacket(IPPacket ipPacket, DateTime time)
    {
        string srcIP = ipPacket.SourceAddress.ToString();
        string dstIP = ipPacket.DestinationAddress.ToString();
        string protocol = "IP";
        int srcPort = 0;
        int dstPort = 0;

        var tcp = ipPacket.Extract<TcpPacket>();
        var udp = ipPacket.Extract<UdpPacket>();

        if (tcp != null)
        {
            protocol = "TCP";
            srcPort = tcp.SourcePort;
            dstPort = tcp.DestinationPort;
        }
        else if (udp != null)
        {
            protocol = "UDP";
            srcPort = udp.SourcePort;
            dstPort = udp.DestinationPort;
        }

        if (srcPort == 102 || dstPort == 102)
        {
            packetCount++;
            lock (consoleLock)
            {
                Console.WriteLine($"[{time:HH:mm:ss.fff}] {srcIP}:{srcPort} => {dstIP}:{dstPort} ({protocol})");
                Console.WriteLine("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
            }
        }
    }

    static void SaveToSQLite(string deviceName)
    {
        var conn = new SQLiteConnection("Data Source=config.db");
        conn.Open();

        var cmd = new SQLiteCommand(@"
        CREATE TABLE IF NOT EXISTS nms_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_name TEXT NOT NULL
        );", conn);
        cmd.ExecuteNonQuery();
        cmd.Dispose();

        var insertCmd = new SQLiteCommand("INSERT INTO nms_config(device_name) VALUES (@name);", conn);
        insertCmd.Parameters.AddWithValue("@name", deviceName);
        insertCmd.ExecuteNonQuery();
        insertCmd.Dispose();

        conn.Close();
        conn.Dispose();
        Console.WriteLine("설정이 저장되었습니다.");
    }

    static string ExtractGuid(string deviceName)
    {
        Regex guidRegex = new Regex(@"\{([A-F0-9\-]+)\}");
        Match match = guidRegex.Match(deviceName);
        return match.Success ? match.Groups[1].Value : "Unknown";
    }

    static void WaitForKeyPress()
    {
        Console.WriteLine("\n계속하려면 아무 키나 누르세요...");
        Console.ReadKey();
    }
}
