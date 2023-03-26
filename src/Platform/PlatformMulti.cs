#if !NETPLAT_WIN32  && !__ANDROID__ && !__CONSTRAINED__ && !WINDOWS_RUNTIME && !UNITY_STANDALONE_LINUX
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace Lidgren.Network
{

    public static partial class NetUtility
    {
        public static NetUtiPlatform NetUtilPlatform
        {
            get { return m_netUtilPlatform; }
        }
        private static NetUtiPlatform m_netUtilPlatform = NetUtiPlatform.Win32;

        private static readonly long s_timeInitialized = Stopwatch.GetTimestamp();
        private static readonly double s_dInvFreq = 1.0 / (double)Stopwatch.Frequency;


        private static byte[] s_randomMacBytes;

        public static void SetNetUtilPlatform(NetUtiPlatform mode)
        {
            m_netUtilPlatform = mode;
        }

        static NetUtility()
        {
            s_randomMacBytes = new byte[8];
            MWCRandom.Instance.NextBytes(s_randomMacBytes);
        }


        [CLSCompliant(false)]
        public static ulong GetPlatformSeed(int seedInc)
        {
            if (m_netUtilPlatform == NetUtiPlatform.Win32)
            {
                ulong seed = (ulong)System.Diagnostics.Stopwatch.GetTimestamp();
                return seed ^ ((ulong)Environment.WorkingSet + (ulong)seedInc);
            }
            else
            {
                ulong seed = (ulong)Environment.TickCount + (ulong)seedInc;
                return seed ^ ((ulong)(new object().GetHashCode()) << 32);
            }
        }

        public static double Now { get { return (double)(Stopwatch.GetTimestamp() - s_timeInitialized) * s_dInvFreq; } }

        private static NetworkInterface GetNetworkInterface()
        {
            var computerProperties = IPGlobalProperties.GetIPGlobalProperties();
            if (computerProperties == null)
                return null;

            var nics = NetworkInterface.GetAllNetworkInterfaces();
            if (nics == null || nics.Length < 1)
                return null;

            NetworkInterface best = null;
            foreach (NetworkInterface adapter in nics)
            {
                if (adapter.NetworkInterfaceType == NetworkInterfaceType.Loopback || adapter.NetworkInterfaceType == NetworkInterfaceType.Unknown)
                    continue;
                if (!adapter.Supports(NetworkInterfaceComponent.IPv4))
                    continue;
                if (best == null)
                    best = adapter;
                if (adapter.OperationalStatus != OperationalStatus.Up)
                    continue;

                // make sure this adapter has any ipv4 addresses
                IPInterfaceProperties properties = adapter.GetIPProperties();
                foreach (UnicastIPAddressInformation unicastAddress in properties.UnicastAddresses)
                {
                    if (unicastAddress != null && unicastAddress.Address != null && unicastAddress.Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        // Yes it does, return this network interface.
                        return adapter;
                    }
                }
            }
            return best;
        }

        /// <summary>
        /// If available, returns the bytes of the physical (MAC) address for the first usable network interface
        /// </summary>
        public static byte[] GetMacAddressBytes()
        {
            if (m_netUtilPlatform == NetUtiPlatform.Win32)
            {
                var ni = GetNetworkInterface();
                if (ni == null)
                    return null;
                return ni.GetPhysicalAddress().GetAddressBytes();
            }
            else
            {
                return s_randomMacBytes;
            }
        }

        public static IPAddress GetBroadcastAddress()
        {
            if (m_netUtilPlatform == NetUtiPlatform.Win32)
            {
                var ni = GetNetworkInterface();
                if (ni == null)
                    return null;

                var properties = ni.GetIPProperties();
                foreach (UnicastIPAddressInformation unicastAddress in properties.UnicastAddresses)
                {
                    if (unicastAddress != null && unicastAddress.Address != null && unicastAddress.Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        var mask = unicastAddress.IPv4Mask;
                        byte[] ipAdressBytes = unicastAddress.Address.GetAddressBytes();
                        byte[] subnetMaskBytes = mask.GetAddressBytes();

                        if (ipAdressBytes.Length != subnetMaskBytes.Length)
                            throw new ArgumentException("Lengths of IP address and subnet mask do not match.");

                        byte[] broadcastAddress = new byte[ipAdressBytes.Length];
                        for (int i = 0; i < broadcastAddress.Length; i++)
                        {
                            broadcastAddress[i] = (byte)(ipAdressBytes[i] | (subnetMaskBytes[i] ^ 255));
                        }
                        return new IPAddress(broadcastAddress);
                    }
                }
                return IPAddress.Broadcast;
            }
            else
            {
                return IPAddress.Broadcast;
            }
        }

        /// <summary>
        /// Gets my local IPv4 address (not necessarily external) and subnet mask
        /// </summary>
        public static IPAddress GetMyAddress(out IPAddress mask)
        {
            if (m_netUtilPlatform == NetUtiPlatform.Win32)
            {
                var ni = GetNetworkInterface();
                if (ni == null)
                {
                    mask = null;
                    return null;
                }

                IPInterfaceProperties properties = ni.GetIPProperties();
                foreach (UnicastIPAddressInformation unicastAddress in properties.UnicastAddresses)
                {
                    if (unicastAddress != null && unicastAddress.Address != null && unicastAddress.Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        mask = unicastAddress.IPv4Mask;
                        return unicastAddress.Address;
                    }
                }

                mask = null;
                return null;
            }
            else
            {
                mask = null;
#if UNITY_ANDROID || UNITY_STANDALONE_OSX || UNITY_STANDALONE_WIN || UNITY_STANDALONE_LINUX || UNITY_IOS
			try
			{
				if (!(UnityEngine.Application.internetReachability == UnityEngine.NetworkReachability.NotReachable))
				{
					return null;
				}
				return IPAddress.Parse(UnityEngine.Network.player.externalIP);
			}
			catch // Catch Access Denied errors
			{
				return null;
			}
#endif
                return null;
            }
        }

        public static void Sleep(int milliseconds)
        {
            System.Threading.Thread.Sleep(milliseconds);
        }

        public static IPAddress CreateAddressFromBytes(byte[] bytes)
        {
            return new IPAddress(bytes);
        }

        private static readonly SHA256 s_sha256 = SHA256.Create();
        private static readonly SHA1 s_sha1 = SHA1.Create();
        public static byte[] ComputeSHAHash(byte[] bytes, int offset, int count)
        {
            if (m_netUtilPlatform == NetUtiPlatform.Win32)
                return s_sha256.ComputeHash(bytes, offset, count);
            else
                return s_sha1.ComputeHash(bytes, offset, count);
        }
    }

    public static partial class NetTime
    {
        private static readonly long s_timeInitialized_Win32 = Stopwatch.GetTimestamp();
        private static readonly double s_dInvFreq = 1.0 / (double)Stopwatch.Frequency;

        private static readonly long s_timeInitialized = Environment.TickCount;

        /// <summary>
        /// Get number of seconds since the application started
        /// </summary>
        public static double Now
        {
            get
            {
                if (NetUtility.NetUtilPlatform == NetUtiPlatform.Win32)
                    return (double)(Stopwatch.GetTimestamp() - s_timeInitialized_Win32) * s_dInvFreq;
                else
                    return (double)((uint)Environment.TickCount - s_timeInitialized) / 1000.0;
            }
        }
    }
}
#endif