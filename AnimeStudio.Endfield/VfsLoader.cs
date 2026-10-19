using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;

namespace AnimeStudio.Endfield;

/// <summary>
/// VFS block loader: reads encrypted .blc and .chk files from the
/// StreamingAssets/VFS folder. Faithful port of fluffy-dumper/vfs/src/loader.rs.
/// </summary>
public sealed class VfsLoader
{
    private const string VfsDir = "VFS";

    private readonly string _vfsPath;
    private readonly byte[] _chachaKey;
    private readonly List<string> _fallbackVfsPaths = new();

    public VfsLoader(string streamingAssetsPath, byte[] chacha20Key)
    {
        if (streamingAssetsPath is null) throw new ArgumentNullException(nameof(streamingAssetsPath));
        if (chacha20Key is null) throw new ArgumentNullException(nameof(chacha20Key));
        if (chacha20Key.Length != 32)
            throw new ArgumentException("ChaCha20 key must be 32 bytes", nameof(chacha20Key));

        _vfsPath = Path.Combine(streamingAssetsPath, VfsDir);
        _chachaKey = (byte[])chacha20Key.Clone();
        DetectSiblingLayers(streamingAssetsPath);
    }

    /// <summary>
    /// v1.4.4+ splits data across two VFS layers: the base install
    /// (Endfield_Data/StreamingAssets) and the hot-update overlay
    /// (Endfield_Data/Persistent). Chunks referenced by one layer's .blc
    /// often live in the other, so register the sibling as a read fallback.
    /// </summary>
    private void DetectSiblingLayers(string streamingAssetsPath)
    {
        try
        {
            string abs = Path.GetFullPath(streamingAssetsPath)
                .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            string? dataDir = Path.GetDirectoryName(abs);
            if (dataDir is null) return;

            foreach (string sibling in new[] { "StreamingAssets", "Persistent" })
            {
                string candidate = Path.Combine(dataDir, sibling);
                if (!Directory.Exists(Path.Combine(candidate, VfsDir))) continue;
                if (string.Equals(Path.GetFullPath(candidate), abs, StringComparison.Ordinal))
                    continue;
                _fallbackVfsPaths.Add(Path.Combine(candidate, VfsDir));
            }
        }
        catch
        {
            // Path probing is best-effort; extraction still works from the primary layer.
        }
    }

    public string VfsPath => _vfsPath;

    /// <summary>
    /// Resolves a chunk file, preferring the primary layer and falling back to
    /// sibling layers when the chunk was shipped only in the other one.
    /// </summary>
    private string? ResolveChunkPath(string dirName, string fileName)
    {
        string primary = Path.Combine(_vfsPath, dirName, fileName);
        if (File.Exists(primary)) return primary;

        foreach (string fallback in _fallbackVfsPaths)
        {
            string candidate = Path.Combine(fallback, dirName, fileName);
            if (File.Exists(candidate)) return candidate;
        }
        return null;
    }

    public BlockMainInfo LoadBlockInfo(BlockType bt)
    {
        string dirName = BlockHashes.GetDirName(bt);
        string blockFilePath = Path.Combine(_vfsPath, dirName, dirName + ".blc");

        if (!File.Exists(blockFilePath))
        {
            // Block indexes may live only in the sibling layer (e.g. language
            // voice blocks are shipped via the hot-update overlay).
            string? fallback = ResolveChunkPath(dirName, dirName + ".blc");
            if (fallback is null)
            {
                throw new DirectoryNotFoundException($"block directory not found: {dirName}");
            }
            blockFilePath = fallback;
        }

        byte[] blockData = File.ReadAllBytes(blockFilePath);

        if (blockData.Length < Keys.BlockHeadLen)
        {
            throw new InvalidDataException("block file too short");
        }

        Span<byte> nonce = stackalloc byte[Keys.BlockHeadLen];
        blockData.AsSpan(0, Keys.BlockHeadLen).CopyTo(nonce);

        int payloadLen = blockData.Length - Keys.BlockHeadLen;
        var decrypted = new byte[payloadLen];
        Buffer.BlockCopy(blockData, Keys.BlockHeadLen, decrypted, 0, payloadLen);

        var cipher = new ChaCha20(_chachaKey, nonce, 1);
        cipher.ApplyKeystream(decrypted);

        return VfsParser.Parse(decrypted, verifyCrc: true);
    }

    /// <summary>
    /// Loads a block index when that block is available in the current VFS layer.
    /// Optional blocks may be represented by neither a directory nor a .blc file
    /// (and some game versions leave an empty directory behind). Both forms mean
    /// "not present"; malformed or unreadable block indexes still throw.
    /// </summary>
    public bool TryLoadBlockInfo(
        BlockType bt,
        [NotNullWhen(true)] out BlockMainInfo? info)
    {
        try
        {
            info = LoadBlockInfo(bt);
            return true;
        }
        catch (DirectoryNotFoundException)
        {
            info = null;
            return false;
        }
        catch (FileNotFoundException)
        {
            info = null;
            return false;
        }
    }

    public long ExtractFile(BlockType bt, ChunkInfo chunk, FileInfo file, Stream writer)
    {
        if (chunk is null) throw new ArgumentNullException(nameof(chunk));
        if (file is null) throw new ArgumentNullException(nameof(file));
        if (writer is null) throw new ArgumentNullException(nameof(writer));

        string dirName = BlockHashes.GetDirName(bt);
        string? chunkPath = ResolveChunkPath(dirName, chunk.FileName());

        if (chunkPath is null)
        {
            throw new FileNotFoundException(
                $"chunk file not found: {chunk.FileName()}", Path.Combine(_vfsPath, dirName, chunk.FileName()));
        }

        using var stream = new FileStream(
            chunkPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 64 * 1024,
            useAsync: false);

        stream.Seek(file.Offset, SeekOrigin.Begin);

        long bytesWritten = 0;
        long fileLen = file.Length;
        var buffer = new byte[64 * 1024];

        if (file.UseEncrypt)
        {
            Span<byte> nonce = stackalloc byte[12];
            BinaryPrimitives.WriteInt32LittleEndian(nonce.Slice(0, 4), Keys.VfsProtoVersion);
            BinaryPrimitives.WriteInt64LittleEndian(nonce.Slice(4, 8), file.IvSeed);

            var cipher = new ChaCha20(_chachaKey, nonce, 1);

            long remaining = fileLen;
            while (remaining > 0)
            {
                int toRead = (int)Math.Min(remaining, buffer.Length);
                int read = stream.Read(buffer, 0, toRead);
                if (read == 0) break;

                cipher.ApplyKeystream(buffer.AsSpan(0, read));
                writer.Write(buffer, 0, read);
                bytesWritten += read;
                remaining -= read;
            }
        }
        else
        {
            long remaining = fileLen;
            while (remaining > 0)
            {
                int toRead = (int)Math.Min(remaining, buffer.Length);
                int read = stream.Read(buffer, 0, toRead);
                if (read == 0) break;

                writer.Write(buffer, 0, read);
                bytesWritten += read;
                remaining -= read;
            }
        }

        return bytesWritten;
    }

    public byte[] ExtractFileToBytes(BlockType bt, ChunkInfo chunk, FileInfo file)
    {
        using var ms = new MemoryStream(checked((int)Math.Max(0, file.Length)));
        ExtractFile(bt, chunk, file, ms);
        return ms.ToArray();
    }
}
