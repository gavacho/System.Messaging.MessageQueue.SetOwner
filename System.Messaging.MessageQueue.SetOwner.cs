using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace System.Messaging
{
	public static partial class MessageQueueExtensions
	{
		private static class Win32
		{
			public const int SECURITY_DESCRIPTOR_REVISION = 1;
			public const int OWNER_SECURITY_INFORMATION = 1;

			[StructLayout(LayoutKind.Sequential)]
			public class SECURITY_DESCRIPTOR
			{
				public byte revision;
				public byte size;
				public short control;
				public IntPtr owner;
				public IntPtr group;
				public IntPtr sacl;
				public IntPtr dacl;
			}

			[DllImport("advapi32.dll", SetLastError = true)]
			public static extern bool InitializeSecurityDescriptor(SECURITY_DESCRIPTOR SD, int revision);

			[DllImport("advapi32.dll", SetLastError = true)]
			public static extern bool SetSecurityDescriptorOwner(SECURITY_DESCRIPTOR pSecurityDescriptor, byte[] pOwner, bool bOwnerDefaulted);

			[DllImport("mqrt.dll", SetLastError = true, CharSet = CharSet.Unicode)]
			public static extern bool MQSetQueueSecurity(string lpwcsFormatName, int SecurityInformation, SECURITY_DESCRIPTOR pSecurityDescriptor);
		}

		public static void SetOwner(this MessageQueue queue, string name, bool ownerDefaulted = false)
		{
			SetOwner(queue, new NTAccount(name), ownerDefaulted);
		}

		public static void SetOwner(this MessageQueue queue, IdentityReference identity, bool ownerDefaulted = false)
		{
			var securityIdentifier = (SecurityIdentifier)identity.Translate(typeof(SecurityIdentifier));
			SetOwner(queue, securityIdentifier, ownerDefaulted);
		}

		public static void SetOwner(this MessageQueue queue, SecurityIdentifier sid, bool ownerDefaulted = false)
		{
			var buffer = new byte[sid.BinaryLength];
			sid.GetBinaryForm(buffer, 0);
			SetOwner(queue, buffer, ownerDefaulted);
		}

		public static void SetOwner(this MessageQueue queue, byte[] sid, bool ownerDefaulted = false)
		{
			var securityDescriptor = new Win32.SECURITY_DESCRIPTOR();
			if (!Win32.InitializeSecurityDescriptor(securityDescriptor, Win32.SECURITY_DESCRIPTOR_REVISION))
				throw new Win32Exception();

			if (!Win32.SetSecurityDescriptorOwner(securityDescriptor, sid, ownerDefaulted))
				throw new Win32Exception();

			if (Win32.MQSetQueueSecurity(queue.FormatName, Win32.OWNER_SECURITY_INFORMATION, securityDescriptor))
				throw new Win32Exception();
		}
	}
}
