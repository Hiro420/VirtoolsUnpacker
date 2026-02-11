using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text;

class VirtoolsUnpacker
{
	const string VIRTOOLS_SIGN = "Nemo Fi\0";
	const int HEADER_SIZE = 64;

	static bool listOnly = false;
	static string OutputRoot = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Dump");

	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	struct Vmo
	{
		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
		public byte[] sign;

		public uint date;
		public uint crc;
		public uint plugin1;
		public uint plugin2;
		public uint flags;
		public uint compcsz;
		public uint objcsz;
		public uint objsz;
		public uint addpath;
		public uint componentsCount;
		public uint objectsCount;
		public uint zero;
		public uint version;
		public uint componentsSize;
	}

	struct ComponentRecord
	{
		public int Id;
		public int Type;
		public int Offset;
		public string Name;
	}

	struct ObjectSlice
	{
		public int Index;
		public int Type;
		public int Id;
		public int Start;
		public int Size;
		public string Name;
	}

	static readonly Dictionary<int, string> TypeNames = new()
	{
		{ 1, "OBJECT" },
		{ 2, "PARAMETERIN" },
		{ 3, "PARAMETEROUT" },
		{ 4, "PARAMETEROPERATION" },
		{ 5, "STATE" },
		{ 6, "BEHAVIORLINK" },
		{ 8, "BEHAVIOR" },
		{ 9, "BEHAVIORIO" },
		{ 10, "SCENE" },
		{ 11, "SCENEOBJECT" },
		{ 12, "RENDERCONTEXT" },
		{ 13, "KINEMATICCHAIN" },
		{ 15, "OBJECTANIMATION" },
		{ 16, "ANIMATION" },
		{ 18, "KEYEDANIMATION" },
		{ 19, "BEOBJECT" },
		{ 20, "SYNCHRO" },
		{ 21, "LEVEL" },
		{ 22, "PLACE" },
		{ 23, "GROUP" },
		{ 24, "SOUND" },
		{ 25, "WAVESOUND" },
		{ 26, "MIDISOUND" },
		{ 27, "ENTITY_2D" },
		{ 28, "SPRITE" },
		{ 29, "SPRITETEXT" },
		{ 30, "MATERIAL" },
		{ 31, "TEXTURE" },
		{ 32, "MESH" },
		{ 33, "ENTITY_3D" },
		{ 34, "CAMERA" },
		{ 35, "TARGETCAMERA" },
		{ 36, "CURVEPOINT" },
		{ 37, "SPRITE3D" },
		{ 38, "LIGHT" },
		{ 39, "TARGETLIGHT" },
		{ 40, "CHARACTER" },
		{ 41, "OBJECT_3D" },
		{ 42, "BODYPART" },
		{ 43, "CURVE" },
		{ 45, "PARAMETERLOCAL" },
		{ 46, "PARAMETER" },
		{ 47, "RENDEROBJECT" },
		{ 48, "INTERFACEOBJECTMANAGER" },
		{ 49, "CRITICALSECTION" },
		{ 50, "GRID" },
		{ 51, "LAYER" },
		{ 52, "DATAARRAY" },
		{ 53, "PATCHMESH" },
		{ 54, "PROGRESSIVEMESH" },
		{ 55, "PARAMETERVARIABLE" },
		{ 56, "POINTCLOUD_3D" },
		{ 57, "VIDEO" },
		{ 58, "MAXCLASSID" },
		{ 80, "OBJECTARRAY" },
		{ 81, "SCENEOBJECTDESC" },
		{ 82, "ATTRIBUTEMANAGER" },
		{ 83, "MESSAGEMANAGER" },
		{ 84, "COLLISIONMANAGER" },
		{ 85, "OBJECTMANAGER" },
		{ 86, "FLOORMANAGER" },
		{ 87, "RENDERMANAGER" },
		{ 88, "BEHAVIORMANAGER" },
		{ 89, "INPUTMANAGER" },
		{ 90, "PARAMETERMANAGER" },
		{ 91, "GRIDMANAGER" },
		{ 92, "SOUNDMANAGER" },
		{ 93, "TIMEMANAGER" },
		{ 94, "VIDEOMANAGER" },
		{ -1, "CUIKBEHDATA" },
	};

	static void Main(string[] args)
	{
		Console.OutputEncoding = Encoding.UTF8;
		Console.WriteLine("\nVirtools (Nemo Fi) extractor\n");

		if (args.Length < 1)
		{
			Console.WriteLine("Usage: VirtoolsUnpacker [options] <file.nmo>");
			Console.WriteLine("Options:\n  -l        list only\n");
			return;
		}

		string? inputFile = null;
		foreach (var a in args)
		{
			if (a == "-l") listOnly = true;
			else if (!a.StartsWith("-")) inputFile = a;
		}

		if (inputFile == null)
		{
			Console.WriteLine("Error: input file not provided.");
			return;
		}
		if (!File.Exists(inputFile))
		{
			Console.WriteLine("Error: file does not exist.");
			return;
		}

		using var fs = new FileStream(inputFile, FileMode.Open, FileAccess.Read, FileShare.Read);
		using var br = new BinaryReader(fs);

		var vmo = ReadStruct<Vmo>(br);

		string sig = Encoding.ASCII.GetString(vmo.sign);
		if (sig != VIRTOOLS_SIGN)
		{
			Console.WriteLine($"Error: unsupported signature: \"{sig}\" (expected Nemo Fi\\0)");
			return;
		}

		Console.WriteLine($"- file:             {inputFile}");
		Console.WriteLine($"- date:             {VirtDate(vmo.date)}");
		Console.WriteLine($"- compcsz:          0x{vmo.compcsz:X8}  componentsSize: 0x{vmo.componentsSize:X8}");
		Console.WriteLine($"- objcsz:           0x{vmo.objcsz:X8}  objsz:          0x{vmo.objsz:X8}");
		Console.WriteLine($"- componentsCount:  {vmo.componentsCount}");
		Console.WriteLine($"- objectsCount:     {vmo.objectsCount}");
		Console.WriteLine($"- version:          {vmo.version >> 24}.{(vmo.version >> 16) & 0xFF}.{(vmo.version >> 8) & 0xFF}.{vmo.version & 0xFF}");

		long need = HEADER_SIZE + (long)vmo.compcsz + (long)vmo.objcsz;
		if (need > fs.Length)
		{
			Console.WriteLine("Error: file truncated (header+blocks exceed file size).");
			return;
		}

		fs.Position = HEADER_SIZE;
		byte[] compRaw = ReadExactBytes(fs, checked((int)vmo.compcsz));
		byte[] objRaw = ReadExactBytes(fs, checked((int)vmo.objcsz));

		byte[] compData = (vmo.componentsSize == vmo.compcsz)
			? compRaw
			: ZlibDecompressExact(compRaw, checked((int)vmo.componentsSize));

		byte[] objData = (vmo.objcsz == vmo.objsz)
			? objRaw
			: ZlibDecompressExact(objRaw, checked((int)vmo.objsz));

		string baseOut = Path.Combine(OutputRoot, Path.GetFileNameWithoutExtension(inputFile));
		string objectsDir = Path.Combine(baseOut, "objects");
		Directory.CreateDirectory(baseOut);
		Directory.CreateDirectory(objectsDir);

		if (!listOnly)
		{
			File.WriteAllBytes(Path.Combine(baseOut, "components.bin"), compData);
			File.WriteAllBytes(Path.Combine(baseOut, "objects.bin"), objData);
		}

		var records = ParseComponentRecords(compData, checked((int)vmo.componentsCount));
		int baseAbs = HEADER_SIZE + checked((int)vmo.componentsSize);
		var slices = BuildObjectSlices(records, baseAbs, checked((int)vmo.objsz));

		Console.WriteLine("\n  idx  start      size       type                 id        name");
		Console.WriteLine("  -------------------------------------------------------------------------");

		string manifestPath = Path.Combine(baseOut, "manifest.tsv");
		using var manifest = new StreamWriter(manifestPath, false, new UTF8Encoding(false));
		manifest.WriteLine("index\tstart\tsize\ttype\tid\tname\tfile");

		int extracted = 0;
		foreach (var s in slices)
		{
			string typeName = TypeNames.TryGetValue(s.Type, out var tn) ? tn : $"TYPE_{s.Type}";
			Console.WriteLine($"  {s.Index,3}  0x{s.Start:X8}  0x{s.Size:X8}  {typeName,-20}  {s.Id,8}  {s.Name}");

			string safeName = SanitizeFileName(s.Name);
			string outName = $"{s.Index:0000}_{typeName}_{s.Id}_{safeName}.bin";
			string outPath = Path.Combine(objectsDir, outName);

			manifest.WriteLine($"{s.Index}\t{s.Start}\t{s.Size}\t{typeName}\t{s.Id}\t{s.Name}\tobjects/{outName}");

			if (!listOnly)
			{
				if (s.Start < 0 || s.Size < 0 || s.Start + s.Size > objData.Length)
					throw new InvalidDataException($"Slice out of range: idx={s.Index} start={s.Start} size={s.Size}");

				File.WriteAllBytes(outPath, objData.AsSpan(s.Start, s.Size).ToArray());
				extracted++;
			}
		}

		if (!listOnly)
			Console.WriteLine($"\nDone. Extracted {extracted} object slices to: {objectsDir}");
		else
			Console.WriteLine($"\nDone. Listed {slices.Count} object slices.");

		Console.WriteLine($"Manifest: {manifestPath}");
	}

	static List<ComponentRecord> ParseComponentRecords(byte[] compData, int count)
	{
		var list = new List<ComponentRecord>(count);
		using var ms = new MemoryStream(compData, writable: false);
		using var br = new BinaryReader(ms);

		for (int i = 0; i < count; i++)
		{
			if (ms.Position + 16 > ms.Length)
				throw new InvalidDataException($"Component record {i}: truncated header.");

			int id = br.ReadInt32();
			int type = br.ReadInt32();
			int offset = br.ReadInt32();
			int nameLen = br.ReadInt32();

			if (nameLen < 0 || ms.Position + nameLen > ms.Length)
				throw new InvalidDataException($"Component record {i}: invalid nameLen={nameLen}.");

			byte[] nameBytes = br.ReadBytes(nameLen);
			string name = DecodeCString(nameBytes);

			list.Add(new ComponentRecord
			{
				Id = id,
				Type = type,
				Offset = offset,
				Name = name
			});
		}

		return list;
	}

	static List<ObjectSlice> BuildObjectSlices(List<ComponentRecord> records, int baseAbs, int objsz)
	{
		if (records.Count == 0)
			return new List<ObjectSlice>();

		records.Sort((a, b) => a.Offset.CompareTo(b.Offset));

		int fileObjEndAbs = baseAbs + objsz;

		int firstSize = records[0].Offset - baseAbs;
		if (firstSize < 0) throw new InvalidDataException("First offset is before objects start.");

		var slices = new List<ObjectSlice>(records.Count + 1);

		slices.Add(new ObjectSlice
		{
			Index = 0,
			Type = 4,
			Id = 0,
			Start = 0,
			Size = firstSize,
			Name = "PARAMETEROPERATION"
		});

		for (int i = 0; i < records.Count; i++)
		{
			int startAbs = records[i].Offset;
			int startRel = startAbs - baseAbs;

			int endAbs;
			if (i + 1 < records.Count)
				endAbs = records[i + 1].Offset;
			else
				endAbs = fileObjEndAbs;

			int size = endAbs - startAbs;
			if (size < 0) throw new InvalidDataException("Offsets not monotonic after sorting.");
			if (startRel < 0) throw new InvalidDataException("Record offset before objects base.");

			slices.Add(new ObjectSlice
			{
				Index = i + 1,
				Type = records[i].Type,
				Id = records[i].Id,
				Start = startRel,
				Size = size,
				Name = string.IsNullOrWhiteSpace(records[i].Name) ? $"unnamed_{i}" : records[i].Name
			});
		}

		return slices;
	}


	static byte[] ZlibDecompressExact(byte[] input, int expectedSize)
	{
		byte[] output = new byte[expectedSize];
		using var ms = new MemoryStream(input, writable: false);
		using var zs = new ZLibStream(ms, CompressionMode.Decompress);

		ReadExact(zs, output);
		return output;
	}

	static void ReadExact(Stream s, byte[] buffer)
	{
		int off = 0;
		while (off < buffer.Length)
		{
			int r = s.Read(buffer, off, buffer.Length - off);
			if (r <= 0)
				throw new InvalidDataException("Decompression ended early (output shorter than expected).");
			off += r;
		}
	}

	static byte[] ReadExactBytes(Stream s, int count)
	{
		byte[] buf = new byte[count];
		int off = 0;
		while (off < count)
		{
			int r = s.Read(buf, off, count - off);
			if (r <= 0) throw new EndOfStreamException("Unexpected EOF.");
			off += r;
		}
		return buf;
	}

	static string DecodeCString(byte[] bytes)
	{
		int n = Array.IndexOf(bytes, (byte)0);
		if (n < 0) n = bytes.Length;
		return Encoding.UTF8.GetString(bytes, 0, n);
	}

	static string SanitizeFileName(string name)
	{
		if (string.IsNullOrEmpty(name)) return "noname";
		foreach (var c in Path.GetInvalidFileNameChars())
			name = name.Replace(c, '_');
		name = name.Replace("..", "_");
		name = name.Trim();
		if (name.Length == 0) name = "noname";
		if (name.Length > 160) name = name.Substring(0, 160);
		return name;
	}

	static T ReadStruct<T>(BinaryReader reader) where T : struct
	{
		int sz = Marshal.SizeOf<T>();
		byte[] bytes = reader.ReadBytes(sz);
		if (bytes.Length != sz) throw new EndOfStreamException("Unexpected EOF while reading header.");

		GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
		try { return Marshal.PtrToStructure<T>(handle.AddrOfPinnedObject()); }
		finally { handle.Free(); }
	}

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
}
