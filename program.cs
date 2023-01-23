using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Runtime.InteropServices;

namespace HASHbrown
{
    class Program
    {
        [DllImport("user32.dll")]
        internal static extern bool OpenClipboard(IntPtr hWndNewOwner);

        [DllImport("user32.dll")]
        internal static extern bool CloseClipboard();

        [DllImport("user32.dll")]
        internal static extern bool SetClipboardData(uint UriFormat, IntPtr data);

        static void Main(string[] args)
        {
            byte[] StringToByte(string input)
            {
                return Encoding.ASCII.GetBytes(input);
            }

            void SetupHashPrompt(string hashType)
            {
                Console.Clear();   
                Console.WriteLine(hashType + " > What would you like to hash?");
            }

            void Clipboard(string input)
            {
                OpenClipboard(IntPtr.Zero);
                var x = Marshal.StringToHGlobalUni(input);
                SetClipboardData(13, x);
                CloseClipboard();
                Marshal.FreeHGlobal(x);
            }

            int option;
            while (true)
            {
                Console.Clear();
                Console.WriteLine("Which hash would you like to use?");
                Console.WriteLine("\n[Hashes] \n" +
                    "[1] SHA1 \n" +
                    "[2] SHA256 \n" +
                    "[3] SHA384 \n" +
                    "[4] SHA512 \n" +
                    "[5] MD5 \n" +
                    "[6] BCRYPT \n");

                option = int.Parse(Console.ReadLine());

                if (option == 1)
                {
                    SetupHashPrompt("sha1");
                    byte[] bytes = StringToByte(Console.ReadLine());
                    SHA1 sha1 = SHA1.Create();
                    byte[] sha1Bytes = sha1.ComputeHash(bytes);
                    string hash = BitConverter.ToString(sha1Bytes).Replace("-", "".ToLower());
                    Console.WriteLine(hash + " Has been created and copied to your clipboard");
                    Clipboard(hash);
                    Thread.Sleep(2500);
                }
                else if (option == 2)
                {
                    SetupHashPrompt("sha256");
                    byte[] bytes = StringToByte(Console.ReadLine());
                    SHA256 sha256 = SHA256.Create();
                    byte[] sha256Bytes = sha256.ComputeHash(bytes);
                    string hash = BitConverter.ToString(sha256Bytes).Replace("-", "".ToLower());
                    Console.WriteLine(hash + " Has been created and copied to your clipboard");
                    Clipboard(hash);
                    Thread.Sleep(2500);
                }
                else if (option == 3)
                {
                    SetupHashPrompt("sha384");
                    byte[] bytes = StringToByte(Console.ReadLine());
                    SHA384 sha384 = SHA384.Create();
                    byte[] sha384Bytes = sha384.ComputeHash(bytes);
                    string hash = BitConverter.ToString(sha384Bytes).Replace("-", "".ToLower());
                    Console.WriteLine(hash + " Has been created and copied to your clipboard");
                    Clipboard(hash);
                    Thread.Sleep(2500);
                }
                else if (option == 4)
                {
                    SetupHashPrompt("sha512");
                    byte[] bytes = StringToByte(Console.ReadLine());
                    SHA512 sha512 = SHA512.Create();
                    byte[] sha512Bytes = sha512.ComputeHash(bytes);
                    string hash = BitConverter.ToString(sha512Bytes).Replace("-", "".ToLower());
                    Console.WriteLine(hash + " Has been created and copied to your clipboard");
                    Clipboard(hash);
                    Thread.Sleep(2500);
                }
                else if (option == 5)
                {
                    SetupHashPrompt("md5");
                    byte[] bytes = StringToByte(Console.ReadLine());
                    MD5 md5 = MD5.Create();
                    byte[] md5Bytes = md5.ComputeHash(bytes);
                    string hash = BitConverter.ToString(md5Bytes).Replace("-", "".ToLower());
                    Console.WriteLine(hash + " Has been created and copied to your clipboard");
                    Clipboard(hash);
                    Thread.Sleep(2500);
                }
                else if (option == 6)
                {
                    SetupHashPrompt("bcrypt");
                    string input = Console.ReadLine();
                    string bcryptHash = BCrypt.Net.BCrypt.HashPassword(input);
                    Console.WriteLine(bcryptHash + " Has been created and copied to your clipboard");
                    Clipboard(bcryptHash);
                    Thread.Sleep(2500);
                }
                else
                {
                    Console.WriteLine(Console.ReadLine() + " is not a valid option.");
                }
            }
        }
    }
}
