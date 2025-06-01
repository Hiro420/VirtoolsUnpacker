using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;

class VirtoolsUnpacker
{
	const string VIRTOOLS_SIGN = "Nemo Fi\0";
	const int BUFFSZ = 4096;
	const string FILE1 = "components";
	const string FILE2 = "objects";
	static string OutputDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Dump");

	static bool listOnly = false;

	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	struct Vmo
	{
		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
		public byte[] sign;
		public uint crc;
		public uint date;
		public uint plugin1;
		public uint plugin2;
		public uint flags;
		public uint compcsz;
		public uint objcsz;
		public uint objsz;
		public uint addpath;
		public uint components;
		public uint objects;
		public uint zero;
		public uint version;
		public uint compsz;
	}

	static void Main(string[] args)
	{
		Console.OutputEncoding = Encoding.UTF8;
		Console.WriteLine($"\nVirtools files unpacker, rewritten by Hiro420");
		Console.WriteLine("GitHub: Hiro420, Original code by aluigi.altervista.org\n");

		if (args.Length < 1)
		{
			Console.WriteLine("Usage: VirtoolsUnpacker [options] <file.EXT>");
			Console.WriteLine("\nOptions:\n-l        lists the archived files\n");
			return;
		}

		Directory.CreateDirectory(OutputDir);

		string? inputFile = null;

		for (int i = 0; i < args.Length; i++)
		{
			if (args[i] == "-l") listOnly = true;
			else if (!args[i].StartsWith("-"))
				inputFile = args[i];
		}

		if (inputFile == null)
		{
			Console.WriteLine("Error: input file not provided.");
			return;
		}

		Console.WriteLine($"- open file:        {inputFile}");

		if (!File.Exists(inputFile))
		{
			Console.WriteLine("Error: file does not exist.");
			return;
		}

		using var fs = new FileStream(inputFile, FileMode.Open, FileAccess.Read);
		using var br = new BinaryReader(fs);

		var vmo = ReadStruct<Vmo>(br);
		long offset = fs.Position;

		if (Encoding.ASCII.GetString(vmo.sign, 0, 4) == "VXBG")
		{
			int extracted = VxbgExtract(br, fs);
			Console.WriteLine($"\n- {extracted} files {(listOnly ? "listed" : "extracted")}\n");
			return;
		}

		if (Encoding.ASCII.GetString(vmo.sign) != VIRTOOLS_SIGN)
		{
			Console.WriteLine($"- file seems invalid, its signature is \"{Encoding.ASCII.GetString(vmo.sign)}\"");
			Console.Write("- do you want to scan it for valid Virtools data (y/N)? ");
			string? ans = Console.ReadLine();
			if (ans?.ToLower() != "y") return;

			offset = VirtoolsScan(br, fs);
			if (offset == 0)
			{
				Console.WriteLine("\nError: no valid signature found");
				return;
			}
			Console.WriteLine($"- Virtools signature found at offset 0x{offset:X8}");
			fs.Seek(offset, SeekOrigin.Begin);
			vmo = ReadStruct<Vmo>(br);
		}

		Console.WriteLine($"- date              {VirtDate(vmo.date)}");
		Console.WriteLine($"- components:       {vmo.components}");
		Console.WriteLine($"- objects:          {vmo.objects}");
		Console.WriteLine($"- version:          {vmo.version >> 24}.{(vmo.version >> 16) & 0xFF}.{(vmo.version >> 8) & 0xFF}.{vmo.version & 0xFF}");

		Console.WriteLine("\n- additional raw info:");
		Console.WriteLine($"  signature         {Encoding.ASCII.GetString(vmo.sign)}");
		Console.WriteLine($"  crc               {vmo.crc:X8}");
		Console.WriteLine($"  plugin1           {vmo.plugin1:X8}");
		Console.WriteLine($"  plugin2           {vmo.plugin2:X8}");
		Console.WriteLine($"  flags             {vmo.flags:X8}");
		Console.WriteLine($"  compcsz           {vmo.compcsz:X8}");
		Console.WriteLine($"  objcsz            {vmo.objcsz:X8}");
		Console.WriteLine($"  objsz             {vmo.objsz:X8}");
		Console.WriteLine($"  addpath           {vmo.addpath:X8}");
		Console.WriteLine($"  components        {vmo.components:X8}");
		Console.WriteLine($"  objects           {vmo.objects:X8}");
		Console.WriteLine($"  zero              {vmo.zero:X8}");
		Console.WriteLine($"  version           {vmo.version:X8}");
		Console.WriteLine($"  compsz            {vmo.compsz:X8}");

		long totalSize = vmo.compcsz + vmo.objcsz + Marshal.SizeOf<Vmo>();
		if (totalSize > fs.Length)
		{
			Console.WriteLine("\nError: components and objects exceed file size");
			return;
		}

		Console.WriteLine("\n  insize     outsize    filename");
		Console.WriteLine("  ------------------------------");

		if (listOnly)
		{
			Console.WriteLine($"  {vmo.compcsz,-10} {vmo.compsz,-10} {FILE1}");
			Console.WriteLine($"  {vmo.objcsz,-10} {vmo.objsz,-10} {FILE2}");
		}
		else
		{
			VirtoolsCompobj(fs, FILE1, vmo.compcsz, vmo.compsz);
			fs.Seek(offset + vmo.compcsz, SeekOrigin.Begin);
			VirtoolsCompobj(fs, FILE2, vmo.objcsz, vmo.objsz);
		}

		fs.Seek(offset + vmo.compcsz + vmo.objcsz, SeekOrigin.Begin);
		int fileCount = 2;

		while (true)
		{
			if (fs.Position + 4 > fs.Length) break;
			uint len = br.ReadUInt32();
			if (len >= BUFFSZ) break;

			byte[] nameBytes = br.ReadBytes((int)len);
			if (nameBytes.Length < len) break;

			string name = Encoding.UTF8.GetString(nameBytes);
			if (string.IsNullOrEmpty(name)) break;

			if (fs.Position + 4 > fs.Length) break;
			uint size = br.ReadUInt32();
			Console.WriteLine($"             {size,-10} {name}");

			if (listOnly)
			{
				fs.Seek(size, SeekOrigin.Current);
			}
			else
			{
				CheckBadName(ref name);
				GetFile(fs, name, size);
			}

			fileCount++;
		}

		Console.WriteLine($"\n- {fileCount} files {(listOnly ? "listed" : "extracted")}\n");
	}

	static int VxbgExtract(BinaryReader br, FileStream fs)
	{
		uint offset, start, size;
		int files = 0;
		byte[] fname = new byte[BUFFSZ];
		int c;

		fs.Seek(4, SeekOrigin.Begin);
		if (!TryReadUInt32(br, out offset)) return files;

		Console.WriteLine("\n  offset   size       filename");
		Console.WriteLine("  ----------------------------");

		offset += 8;
		start = offset;

		while (fs.Position < start)
		{
			for (int i = 0; i < BUFFSZ; i++)
			{
				c = fs.ReadByte();
				if (c < 0) return files;
				fname[i] = (byte)c;
				if (c == 0) break;
			}

			if (!TryReadUInt32(br, out size)) return files;

			string name = Encoding.UTF8.GetString(fname, 0, Array.IndexOf(fname, (byte)0));
			Console.WriteLine($"  {offset:X8} {size,-10} {name}");

			if (!listOnly)
				GetFile(fs, name, size, (int)offset);

			offset += size;
			files++;
		}

		return files;
	}

	// Utility to safely read UInt32
	static bool TryReadUInt32(BinaryReader br, out uint result)
	{
		result = 0;
		try
		{
			result = br.ReadUInt32();
			return true;
		}
		catch
		{
			return false;
		}
	}

	static T ReadStruct<T>(BinaryReader reader) where T : struct
	{
		byte[] bytes = reader.ReadBytes(Marshal.SizeOf<T>());
		GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
		T theStruct = Marshal.PtrToStructure<T>(handle.AddrOfPinnedObject());
		handle.Free();
		return theStruct;
	}

	// STUBS for compilation
	static string VirtDate(uint val)
	{
		int year = (int)((val >> 25) & 0x7F) + 1980;
		int month = (int)((val >> 21) & 0x0F);
		int day = (int)((val >> 16) & 0x1F);
		int hour = (int)((val >> 11) & 0x1F);
		int minute = (int)((val >> 5) & 0x3F);
		int second = (int)((val & 0x1F) * 2);
		return $"{year:D4}-{month:D2}-{day:D2} {hour:D2}:{minute:D2}:{second:D2}";
	}

	static uint VirtoolsScan(BinaryReader br, FileStream fs)
	{
		byte[] signature = Encoding.ASCII.GetBytes(VIRTOOLS_SIGN);
		byte[] buffer = new byte[BUFFSZ];

		fs.Seek(0, SeekOrigin.Begin);

		while (fs.Position < fs.Length)
		{
			int read = fs.Read(buffer, 0, buffer.Length);
			for (int i = 0; i <= read - signature.Length; i++)
			{
				bool match = true;
				for (int j = 0; j < signature.Length; j++)
				{
					if (buffer[i + j] != signature[j])
					{
						match = false;
						break;
					}
				}

				if (match)
					return (uint)(fs.Position - read + i);
			}

			fs.Seek(-(signature.Length - 1), SeekOrigin.Current); // Overlap for partial match
		}

		return 0;
	}

	static void VirtoolsCompobj(FileStream fs, string fname, uint inSize, uint outSize)
	{
		byte[] inData = new byte[inSize];
		fs.Read(inData, 0, (int)inSize);

		using var inputStream = new MemoryStream(inData);
		using var deflate = new System.IO.Compression.DeflateStream(inputStream, System.IO.Compression.CompressionMode.Decompress);
		byte[] outData = new byte[outSize];
		deflate.Read(outData, 0, (int)outSize);

		File.WriteAllBytes(Path.Combine(OutputDir, fname), outData);
		Console.WriteLine($"  {inSize,-10} {outSize,-10} {fname}");
	}

	static void CheckBadName(ref string name)
	{
		foreach (var c in Path.GetInvalidFileNameChars())
			name = name.Replace(c, '_');

		name = name.Replace("..", "_");
	}

	static void GetFile(FileStream fs, string fname, uint size, int offset = -1)
	{
		long curOffset = fs.Position;
		if (offset >= 0)
			fs.Seek(offset, SeekOrigin.Begin);

		byte[] buffer = new byte[size];
		int bytesRead = fs.Read(buffer, 0, (int)size);
		if (bytesRead != size)
			throw new IOException("Failed to read the expected number of bytes.");

		File.WriteAllBytes(Path.Combine(OutputDir, fname), buffer);
		// Console.WriteLine($"             {size,-10} {fname}");
		fs.Position = curOffset;
	}
}
