using SharpPcap;
using System;
using System.Data.SQLite;

class Program
{
    static void Main()
    {
        var devices = CaptureDeviceList.Instance;

        if(devices.Count < 1)
        {
            Console.WriteLine("네트워크 디바이스를 찾을 수 없습니다.");
            return;
        }

        Console.WriteLine("네트워크 어댑터 목록:");
        for(int i = 0; i <devices.Count; i++)
        {
            Console.WriteLine($"{i}: {devices[i].Description}");
        }

        Console.WriteLine("사용할 네트워크 번호를 선택하세요");
        int index = int.Parse(Console.ReadLine());

        var selectedDevice = devices[index];
        Console.WriteLine($"선택한 어댑터: {selectedDevice.Description}");

        SaveToSqllite(selectedDevice.Name);

    }
    static void SaveToSqllite(String deviceName)
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
        insertCmd.Parameters.AddWithValue("@name",deviceName);
        insertCmd.ExecuteNonQuery();
        insertCmd.Dispose();

        conn.Close();
        conn.Dispose();
        Console.WriteLine("설정이 저장되었습니다.");

    }

}
