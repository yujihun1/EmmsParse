using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;
using System;
using System.Data.SQLite;
using System.Collections.Generic;
using System.Text.RegularExpressions;

class Program
{
    static void Main()
    {
        Console.WriteLine("패킷 캡처 프로그램 시작...");
        Console.WriteLine($"SharpPcap 버전: {SharpPcap.Version.VersionString}");

        // 모든 네트워크 어댑터 가져오기
        var devices = LibPcapLiveDeviceList.Instance;

        if (devices.Count < 1)
        {
            Console.WriteLine("사용 가능한 네트워크 어댑터가 없습니다.");
            Console.WriteLine("Npcap 또는 WinPcap이 설치되어 있는지 확인하세요.");
            Console.WriteLine("다운로드: https://npcap.com");
            WaitForKeyPress();
            return;
        }

        // 어댑터 목록 표시
        Console.WriteLine("\n사용 가능한 네트워크 어댑터 목록:");
        Console.WriteLine("----------------------------------------");

        for (int i = 0; i < devices.Count; i++)
        {
            var dev = devices[i];
            // 디바이스 이름에서 GUID 추출
            string guid = ExtractGuid(dev.Name);
            Console.WriteLine($"{i}: {dev.Description} [{guid}]");

            // 어댑터의 네트워크 주소 표시 (있을 경우)
            if (dev.Addresses.Count > 0)
            {
                foreach (var addr in dev.Addresses)
                {
                    if (addr.Addr != null && addr.Addr.ipAddress != null)
                    {
                        Console.WriteLine($"   IP: {addr.Addr.ipAddress}");
                    }
                }
            }
        }

        Console.WriteLine("----------------------------------------");
        Console.Write("사용할 어댑터 번호를 입력하세요: ");

        int selectedIndex;
        while (!int.TryParse(Console.ReadLine(), out selectedIndex) ||
               selectedIndex < 0 ||
               selectedIndex >= devices.Count)
        {
            Console.Write("올바른 어댑터 번호를 입력하세요: ");
        }

        var selectedDevice = devices[selectedIndex] as LibPcapLiveDevice;
        Console.WriteLine($"\n선택한 어댑터: {selectedDevice.Description}");

        try
        {
            // 어댑터 열기 전에 상태 확인
            Console.WriteLine("어댑터 열기 시도 중...");

            // 패킷 필터 설정 (옵션) - TCP 및 UDP 패킷만 캡처
            string filter = "tcp or udp";

            // 어댑터 열기
            int readTimeoutMilliseconds = 1000;
            selectedDevice.Open(DeviceMode.Normal, readTimeoutMilliseconds);
            Console.WriteLine("어댑터가 성공적으로 열렸습니다.");

            // 필터 설정 (필요한 경우)
            selectedDevice.Filter = filter;
            Console.WriteLine($"필터가 설정되었습니다: {filter}");

            // 패킷 도착 이벤트 핸들러 등록
            selectedDevice.OnPacketArrival += new PacketArrivalEventHandler(Device_OnPacketArrival);

            // 설정 저장 시도
            try
            {
                SaveToSQLite(selectedDevice.Name);
            }
            catch (Exception ex)
            {
                Console.WriteLine("설정 저장 중 오류: " + ex.Message);
                // 설정 저장 실패해도 계속 진행
            }

            // 패킷 캡처 시작
            Console.WriteLine("\n패킷 캡처를 시작합니다. 중지하려면 Ctrl + C를 누르세요.");
            selectedDevice.StartCapture();

            // Ctrl+C 처리
            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true; // 프로그램 종료 방지
                Console.WriteLine("\n캡처 중지 중...");
                try
                {
                    selectedDevice.StopCapture();
                    selectedDevice.Close();
                    Console.WriteLine("캡처가 중지되었습니다.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine("캡처 중지 오류: " + ex.Message);
                }

                Environment.Exit(0);
            };

            // 메인 스레드 대기
            System.Threading.Thread.Sleep(System.Threading.Timeout.Infinite);
        }
        catch (Exception ex)
        {
            Console.WriteLine("어댑터 열기 실패: " + ex.Message);
            Console.WriteLine("상세 정보: " + ex.ToString());

            Console.WriteLine("\n문제 해결 방법:");
            Console.WriteLine("1. 프로그램을 관리자 권한으로 실행하세요.");
            Console.WriteLine("2. Npcap이 제대로 설치되어 있는지 확인하세요. (https://npcap.com)");
            Console.WriteLine("3. 다른 어댑터를 선택해 보세요.");
            Console.WriteLine("4. 방화벽이 프로그램을 차단하고 있지 않은지 확인하세요.");

            WaitForKeyPress();
        }
    }

    static void Device_OnPacketArrival(object sender, CaptureEventArgs e)
    {
        try
        {
            // 패킷 파싱
            var packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);

            // IPv4 패킷 처리
            var ipv4Packet = packet.Extract<IPv4Packet>();
            if (ipv4Packet != null)
            {
                ProcessIPPacket(ipv4Packet, e.Packet.Timeval.Date);
                return;
            }

            // IPv6 패킷 처리
            var ipv6Packet = packet.Extract<IPv6Packet>();
            if (ipv6Packet != null)
            {
                ProcessIPPacket(ipv6Packet, e.Packet.Timeval.Date);
                return;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"패킷 처리 오류: {ex.Message}");
        }
    }

    static void ProcessIPPacket(IPPacket ipPacket, DateTime time)
    {
        string srcIP = ipPacket.SourceAddress.ToString();
        string dstIP = ipPacket.DestinationAddress.ToString();
        string protocol = "IP";
        int srcPort = 0;
        int dstPort = 0;

        // TCP 패킷 처리
        var tcpPacket = ipPacket.Extract<TcpPacket>();
        if (tcpPacket != null)
        {
            protocol = "TCP";
            srcPort = tcpPacket.SourcePort;
            dstPort = tcpPacket.DestinationPort;
        }
        else
        {
            // UDP 패킷 처리
            var udpPacket = ipPacket.Extract<UdpPacket>();
            if (udpPacket != null)
            {
                protocol = "UDP";
                srcPort = udpPacket.SourcePort;
                dstPort = udpPacket.DestinationPort;
            }
        }

        // 패킷 정보 출력
        if (srcPort > 0 && dstPort > 0)
        {
            Console.WriteLine($"[{time:HH:mm:ss.fff}] {srcIP}:{srcPort} => {dstIP}:{dstPort} ({protocol})");
        }
        else
        {
            Console.WriteLine($"[{time:HH:mm:ss.fff}] {srcIP} => {dstIP} ({protocol})");
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
        // 디바이스 이름에서 GUID 추출 (예: \Device\NPF_{442BE5EB-87B2-432A-BD62-2ACDB5F30BC5})
        Regex guidRegex = new Regex(@"\{([A-F0-9\-]+)\}");
        Match match = guidRegex.Match(deviceName);

        if (match.Success && match.Groups.Count > 1)
        {
            return match.Groups[1].Value;
        }

        return "Unknown";
    }

    static void WaitForKeyPress()
    {
        Console.WriteLine("\n계속하려면 아무 키나 누르세요...");
        Console.ReadKey();
    }
}