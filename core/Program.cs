using System;
using System.Runtime.InteropServices;
using System.Threading;

class Program
{
    // 引入DLL中的函数
    [DllImport("ProtAPIHooker.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void EnableGlobalHook();

    [DllImport("ProtAPIHooker.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void DisableGlobalHook(int password);

    [DllImport("ProtAPIHooker.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void InitializeHook();

    static void Main()
    {
        try
        {
            // 调用初始化钩子的函数，通常在加载DLL时需要先执行这一步
            InitializeHook();

            // 启用全局钩子
            EnableGlobalHook();

            Console.WriteLine("钩子已启用，程序正在运行中");

            // 可以在这里添加其他持续执行的逻辑，如果没有则会一直保持运行状态
            while (true)
            {
                Thread.Sleep(100);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"调用DLL函数时出现错误: {ex.Message}");
        }
    }
}