using System;
using System.Buffers;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.IO;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
enum TransactionType { Transfer, Fee }

sealed class Transaction
{
    public string TxId { get; init; } = "";
    public TransactionType Type { get; init; }
    public string SenderPubKey { get; init; } = "";
    public long Nonce { get; init; }
    public DateTime TimestampUtc { get; init; }
    public JsonDocument? Payload { get; init; }     
    public byte[]? Signature { get; init; }


    public byte[] GetSigningBytes()
    {
        var canonicalPayload = Payload is null
            ? ""
            : CanonicalizeJson(Payload.RootElement);

        var data = $"{(int)Type}|{SenderPubKey}|{Nonce}|{TimestampUtc.ToUniversalTime():O}|{canonicalPayload}";
        return Encoding.UTF8.GetBytes(data);
    }

    public void EnsureValidSyntactically()
    {
        if (string.IsNullOrWhiteSpace(SenderPubKey))
            throw new ArgumentException("SenderPubKey is required.");

        if (Nonce < 0)
            throw new ArgumentOutOfRangeException(nameof(Nonce), "Nonce must be >= 0.");

        if (Payload != null && Payload.RootElement.ValueKind == JsonValueKind.Undefined)
            throw new ArgumentException("Payload is undefined JSON.");
    }

    private static string CanonicalizeJson(JsonElement element)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = false }))
        {
            WriteCanonical(writer, element);
        }
        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    private static void WriteCanonical(Utf8JsonWriter writer, JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var p in element.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal))
                {
                    writer.WritePropertyName(p.Name);
                    WriteCanonical(writer, p.Value);
                }
                writer.WriteEndObject();
                break;

            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in element.EnumerateArray())
                    WriteCanonical(writer, item);
                writer.WriteEndArray();
                break;

            case JsonValueKind.String:
                writer.WriteStringValue(element.GetString());
                break;

            case JsonValueKind.Number:
                if (element.TryGetInt64(out var l)) writer.WriteNumberValue(l);
                else if (element.TryGetDecimal(out var dec)) writer.WriteNumberValue(dec);
                else if (element.TryGetDouble(out var dbl)) writer.WriteNumberValue(dbl);
                else writer.WriteRawValue(element.GetRawText());
                break;

            case JsonValueKind.True: writer.WriteBooleanValue(true); break;
            case JsonValueKind.False: writer.WriteBooleanValue(false); break;
            case JsonValueKind.Null: writer.WriteNullValue(); break;
            case JsonValueKind.Undefined:
                writer.WriteNullValue();
                break;
        }
        writer.Flush();
    }
}

sealed class WorldState
{
    public Dictionary<string, long> Accounts { get; } = new();
    public Dictionary<string, long> Nonces { get; } = new();
    public long FixedFeeMinor { get; set; } = 10_000; 

    public WorldState Clone()
    {
        var ws = new WorldState { FixedFeeMinor = this.FixedFeeMinor };
        foreach (var kv in Accounts) ws.Accounts[kv.Key] = kv.Value;
        foreach (var kv in Nonces) ws.Nonces[kv.Key] = kv.Value;
        return ws;
    }

 
    public void Apply(Transaction tx, int height, DateTime blockTimeUtc)
    {
        if (tx is null) throw new ArgumentNullException(nameof(tx));

        var sender = tx.SenderPubKey;
        var currentNonce = Nonces.TryGetValue(sender, out var cur) ? cur : -1;
        if (tx.Nonce != currentNonce + 1)
            throw new InvalidOperationException($"Bad nonce for {sender}. Expected {currentNonce + 1}, got {tx.Nonce}.");

        if (FixedFeeMinor > 0)
        {
            EnsureAccountExists(sender);
            if (Accounts[sender] < FixedFeeMinor)
                throw new InvalidOperationException("Insufficient balance to pay transaction fee.");
            Accounts[sender] -= FixedFeeMinor;
        }

        switch (tx.Type)
        {
            case TransactionType.Transfer:
                ApplyTransfer(tx);
                break;

            case TransactionType.Fee:
                break;

            default:
                break;
        }

        Nonces[sender] = tx.Nonce;
    }

    private void ApplyTransfer(Transaction tx)
    {
        if (tx.Payload is null) throw new InvalidOperationException("Transfer requires payload.");
        var root = tx.Payload.RootElement;

        var to = GetRequiredString(root, "to");
        var amount = GetRequiredInt64(root, "amountMinor");
        if (amount <= 0) throw new InvalidOperationException("amountMinor must be > 0.");

        EnsureAccountExists(tx.SenderPubKey);
        EnsureAccountExists(to);

        if (Accounts[tx.SenderPubKey] < amount)
            throw new InvalidOperationException("Insufficient balance for transfer.");

        Accounts[tx.SenderPubKey] -= amount;
        Accounts[to] += amount;
    }

    private void EnsureAccountExists(string pubKey)
    {
        if (!Accounts.ContainsKey(pubKey))
            Accounts[pubKey] = 0;
    }

    private static string GetRequiredString(JsonElement obj, string name)
    {
        if (!obj.TryGetProperty(name, out var el) || el.ValueKind != JsonValueKind.String)
            throw new InvalidOperationException($"Missing or invalid '{name}'.");
        var v = el.GetString();
        if (string.IsNullOrWhiteSpace(v))
            throw new InvalidOperationException($"'{name}' cannot be empty.");
        return v!;
    }

    private static long GetRequiredInt64(JsonElement obj, string name)
    {
        if (!obj.TryGetProperty(name, out var el) || !el.TryGetInt64(out var v))
            throw new InvalidOperationException($"Missing or invalid '{name}'.");
        return v;
    }
}
static class HashUtils
{
    public static string ComputeSha256Hex(byte[] data)
    {
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(data);
        return ToHexLower(hash);
    }

    public static string ComputeSha256Hex(string textUtf8)
        => ComputeSha256Hex(Encoding.UTF8.GetBytes(textUtf8));

    public static string ToHexLower(ReadOnlySpan<byte> bytes)
    {
        char[] c = new char[bytes.Length * 2];
        int i = 0;
        foreach (var b in bytes)
        {
            c[i++] = GetHexNibble(b >> 4);
            c[i++] = GetHexNibble(b & 0xF);
        }
        return new string(c);

        static char GetHexNibble(int v) => (char)(v < 10 ? '0' + v : 'a' + (v - 10));
    }

    public static byte[] FromHex(string hex)
    {
        if (hex.Length % 2 != 0) throw new ArgumentException("Invalid hex length.", nameof(hex));
        var bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            var hi = GetNibble(hex[2 * i]);
            var lo = GetNibble(hex[2 * i + 1]);
            bytes[i] = (byte)((hi << 4) | lo);
        }
        return bytes;

        static int GetNibble(char c) =>
            c switch
            {
                >= '0' and <= '9' => c - '0',
                >= 'a' and <= 'f' => c - 'a' + 10,
                >= 'A' and <= 'F' => c - 'A' + 10,
                _ => throw new ArgumentException($"Invalid hex char: {c}")
            };
    }
}
sealed class Block
{
    public int Index { get; init; }
    public DateTime TimestampUtc { get; set; }
    public string PreviousHash { get; init; } = "0";
    public List<Transaction> Transactions { get; init; } = new();
    public int Difficulty { get; init; } = 3;
    public long Nonce { get; set; }
    public string MerkleRoot { get; set; } = "";
    public string Hash { get; set; } = "";

    public string ComputeMerkleRoot()
    {
        var leaves = Transactions.Count == 0
            ? new List<string> { HashUtils.ComputeSha256Hex(Array.Empty<byte>()) }
            : Transactions
                .Select(tx => HashUtils.ComputeSha256Hex(tx.GetSigningBytes()))
                .ToList();

        while (leaves.Count > 1)
        {
            var next = new List<string>(capacity: (leaves.Count + 1) / 2);
            for (int i = 0; i < leaves.Count; i += 2)
            {
                var left = leaves[i];
                var right = (i + 1 < leaves.Count) ? leaves[i + 1] : left;
                var combined = Combine(HashUtils.FromHex(left), HashUtils.FromHex(right));
                next.Add(HashUtils.ComputeSha256Hex(combined));
            }
            leaves = next;
        }

        return leaves[0];

        static byte[] Combine(byte[] a, byte[] b)
        {
            var r = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, r, 0, a.Length);
            Buffer.BlockCopy(b, 0, r, a.Length, b.Length);
            return r;
        }
    }
    public string ComputeHash()
    {
        var baseString =
            $"{Index}|{TimestampUtc.ToUniversalTime():O}|{PreviousHash}|{MerkleRoot}|{Nonce}|{Difficulty}";
        return HashUtils.ComputeSha256Hex(baseString);
    }
}
static class PowMiner
{
    public static void Mine(Block b)
    {
        if (b is null) throw new ArgumentNullException(nameof(b));
        var prefix = new string('0', b.Difficulty);

        b.TimestampUtc = DateTime.UtcNow;
        b.MerkleRoot = b.ComputeMerkleRoot();
        b.Nonce = 0;

        while (true)
        {
            var h = b.ComputeHash();
            if (h.StartsWith(prefix, StringComparison.Ordinal))
            {
                b.Hash = h;
                break;
            }
            b.Nonce++;
        }
    }
}
sealed class Blockchain
{
    public List<Block> Chain { get; } = new();
    public WorldState State { get; private set; } = new();
    public int Difficulty { get; set; } = 3;
    public long FixedFeeMinor
    {
        get => State.FixedFeeMinor;
        set => State.FixedFeeMinor = value;
    }

    public Block CreateGenesis()
    {
        if (Chain.Count > 0) return Chain[0];

        var genesis = new Block
        {
            Index = 0,
            PreviousHash = "0",
            Difficulty = Difficulty,
            Transactions = new List<Transaction>()
        };

        PowMiner.Mine(genesis);

        var temp = State.Clone();
        foreach (var tx in genesis.Transactions)
        {
            tx.EnsureValidSyntactically();
            temp.Apply(tx, genesis.Index, genesis.TimestampUtc);
        }
        State = temp;

        Chain.Add(genesis);
        return genesis;
    }

    public Block Latest =>
        Chain.Count == 0
            ? throw new InvalidOperationException("Nincs blokk a láncban. Először hívd meg a CreateGenesis()-t.")
            : Chain[^1];

    public void AddBlock(Block b)
    {
        if (b is null) throw new ArgumentNullException(nameof(b));

        if (Chain.Count == 0)
        {
            if (b.Index != 0 || b.PreviousHash != "0")
                throw new InvalidOperationException("Az első blokk csak genezis lehet (Index=0, PreviousHash='0'). Használd a CreateGenesis()-t.");
        }
        else
        {
            var last = Latest;
            if (b.Index != last.Index + 1)
                throw new InvalidOperationException($"Hibás Index. Várt: {last.Index + 1}, kapott: {b.Index}.");
            if (!string.Equals(b.PreviousHash, last.Hash, StringComparison.Ordinal))
                throw new InvalidOperationException("PreviousHash nem egyezik az utolsó blokk hash-ével.");
        }

        if (b.Difficulty != Difficulty)
            throw new InvalidOperationException($"Váratlan nehézség: {b.Difficulty}. Várt: {Difficulty}.");

        var expectedMerkle = b.ComputeMerkleRoot();
        if (!string.Equals(b.MerkleRoot, expectedMerkle, StringComparison.Ordinal))
            throw new InvalidOperationException("MerkleRoot eltérés a blokk tartalmához képest.");

        var expectedHash = b.ComputeHash();
        if (!string.Equals(b.Hash, expectedHash, StringComparison.Ordinal))
            throw new InvalidOperationException("A blokk Hash nem egyezik a kiszámolt értékkel.");

        var prefix = new string('0', b.Difficulty);
        if (!b.Hash.StartsWith(prefix, StringComparison.Ordinal))
            throw new InvalidOperationException("A blokk nem felel meg a Proof-of-Work feltételnek.");

        var tempState = State.Clone();
        foreach (var tx in b.Transactions)
        {
            tx.EnsureValidSyntactically();
            tempState.Apply(tx, b.Index, b.TimestampUtc);
        }

        State = tempState;
        Chain.Add(b);
    }

    public bool IsValid()
    {
        if (Chain.Count == 0) return false;

        var tmp = new WorldState { FixedFeeMinor = this.State.FixedFeeMinor };
        Block? prev = null;

        for (int i = 0; i < Chain.Count; i++)
        {
            var blk = Chain[i];

            if (i == 0)
            {
                if (blk.Index != 0 || blk.PreviousHash != "0") return false;
            }
            else
            {
                if (blk.Index != prev!.Index + 1) return false;
                if (!string.Equals(blk.PreviousHash, prev!.Hash, StringComparison.Ordinal)) return false;
            }

            if (blk.Difficulty != Difficulty) return false;

            if (blk.MerkleRoot != blk.ComputeMerkleRoot()) return false;
            if (blk.Hash != blk.ComputeHash()) return false;
            if (!blk.Hash.StartsWith(new string('0', blk.Difficulty), StringComparison.Ordinal)) return false;

            try
            {
                foreach (var tx in blk.Transactions)
                {
                    tx.EnsureValidSyntactically();
                    tmp.Apply(tx, blk.Index, blk.TimestampUtc);
                }
            }
            catch
            {
                return false;
            }

            prev = blk;
        }

        return true;
    }
}

sealed class Mempool
{
    public List<Transaction> Pending { get; } = new();

    public void Add(Transaction tx)
    {
        if (tx is null) throw new ArgumentNullException(nameof(tx));
        tx.EnsureValidSyntactically();
        Pending.Add(tx);
    }

    public List<Transaction> TakeForBlock(int max)
        => Pending
            .OrderBy(t => t.SenderPubKey, StringComparer.Ordinal)
            .ThenBy(t => t.Nonce)
            .Take(max)
            .ToList();

    public void Remove(IEnumerable<Transaction> txs)
    {
        foreach (var tx in txs) Pending.Remove(tx);
    }
}

static class MinerService
{
    public static Block MineNextBlock(Blockchain chain, Mempool pool, int maxTxPerBlock = 100)
    {
        if (chain.Chain.Count == 0) chain.CreateGenesis();

        var selected = pool.TakeForBlock(maxTxPerBlock);

        var block = new Block
        {
            Index = chain.Latest.Index + 1,
            PreviousHash = chain.Latest.Hash,
            Difficulty = chain.Difficulty,
            Transactions = selected
        };

        PowMiner.Mine(block);
        chain.AddBlock(block);
        pool.Remove(selected);

        return block;
    }
}

sealed class ChainSnapshot
{
    public int Difficulty { get; set; }
    public long FixedFeeMinor { get; set; }
    public List<Block> Blocks { get; set; } = new();
}

interface IChainStorage
{
    void SaveSnapshot(ChainSnapshot snapshot);
    ChainSnapshot LoadSnapshot();
}

sealed class FileChainStorage : IChainStorage
{
    private readonly string _path;
    private static readonly JsonSerializerOptions _json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    public FileChainStorage(string path)
    {
        _path = path;
    }

    public void SaveSnapshot(ChainSnapshot snapshot)
    {
        var dir = Path.GetDirectoryName(_path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir!);

        var json = JsonSerializer.Serialize(snapshot, _json);
        File.WriteAllText(_path, json, Encoding.UTF8);
    }

    public ChainSnapshot LoadSnapshot()
    {
        if (!File.Exists(_path))
            throw new FileNotFoundException("Chain snapshot not found.", _path);

        var json = File.ReadAllText(_path, Encoding.UTF8);
        var snap = JsonSerializer.Deserialize<ChainSnapshot>(json, _json);
        if (snap is null) throw new InvalidOperationException("Failed to deserialize chain snapshot.");
        return snap;
    }
}

static class BlockchainPersistence
{
    public static void SaveTo(this Blockchain chain, IChainStorage storage)
    {
        var snapshot = new ChainSnapshot
        {
            Difficulty = chain.Difficulty,
            FixedFeeMinor = chain.State.FixedFeeMinor,
            Blocks = new List<Block>(chain.Chain)
        };
        storage.SaveSnapshot(snapshot);
    }

    public static void LoadFrom(this Blockchain chain, IChainStorage storage)
    {
        var snap = storage.LoadSnapshot();

        chain.Difficulty = snap.Difficulty;

        chain.Chain.Clear();
        chain.Chain.AddRange(snap.Blocks);

        if (!chain.IsValid())
            throw new InvalidOperationException("Loaded chain is invalid.");

        var tmp = new WorldState { FixedFeeMinor = snap.FixedFeeMinor };
        for (int i = 0; i < chain.Chain.Count; i++)
        {
            var blk = chain.Chain[i];
            foreach (var tx in blk.Transactions)
            {
                tx.EnsureValidSyntactically();
                tmp.Apply(tx, blk.Index, blk.TimestampUtc);
            }
        }

        chain.State.FixedFeeMinor = snap.FixedFeeMinor;
        chain.State.Accounts.Clear();
        foreach (var kv in tmp.Accounts) chain.State.Accounts[kv.Key] = kv.Value;
        chain.State.Nonces.Clear();
        foreach (var kv in tmp.Nonces) chain.State.Nonces[kv.Key] = kv.Value;
    }
}

static class Api
{
    public static WebApplication Build(string[] args, Blockchain chain, Mempool pool, IChainStorage? storage = null)
    {
        var builder = WebApplication.CreateBuilder(args);
        var app = builder.Build();

        app.MapGet("/", () => Results.Text("MiniChain API running"));

        app.MapGet("/chain", () =>
            Results.Json(new
            {
                height = chain.Chain.Count - 1,
                difficulty = chain.Difficulty,
                blocks = chain.Chain.Select(b => new
                {
                    b.Index,
                    b.TimestampUtc,
                    b.Hash,
                    b.PreviousHash,
                    txCount = b.Transactions.Count
                })
            })
        );

        app.MapGet("/validate", () => Results.Json(new { valid = chain.IsValid() }));

        app.MapGet("/accounts/{pubKey}", (string pubKey) =>
        {
            chain.State.Accounts.TryGetValue(pubKey, out var bal);
            return Results.Json(new { pubKey, balanceMinor = bal });
        });

        app.MapPost("/tx", async (HttpContext http) =>
        {
            var dto = await http.Request.ReadFromJsonAsync<NewTxDto>();
            if (dto is null) return Results.BadRequest("Invalid JSON.");

            try
            {
                var tx = dto.ToTransaction();
                pool.Add(tx);
                return Results.Ok(new { accepted = true, type = tx.Type.ToString(), sender = tx.SenderPubKey, nonce = tx.Nonce });
            }
            catch (Exception ex)
            {
                return Results.BadRequest(new { error = ex.Message });
            }
        });

        app.MapPost("/mine", (int? maxTxPerBlock) =>
        {
            try
            {
                var blk = MinerService.MineNextBlock(chain, pool, maxTxPerBlock ?? 100);
                if (storage != null) chain.SaveTo(storage);
                return Results.Json(new { index = blk.Index, hash = blk.Hash, nonce = blk.Nonce, txCount = blk.Transactions.Count });
            }
            catch (Exception ex)
            {
                return Results.BadRequest(new { error = ex.Message });
            }
        });

        return app;
    }

    internal sealed class NewTxDto
    {
        public TransactionType Type { get; set; }
        public string SenderPubKey { get; set; } = "";
        public long Nonce { get; set; }
        public DateTime? TimestampUtc { get; set; }
        public JsonElement? Payload { get; set; }

        public Transaction ToTransaction()
        {
            JsonDocument? payloadDoc = null;
            if (Payload.HasValue)
                payloadDoc = JsonDocument.Parse(Payload.Value.GetRawText());

            return new Transaction
            {
                Type = Type,
                SenderPubKey = SenderPubKey,
                Nonce = Nonce,
                TimestampUtc = (TimestampUtc ?? DateTime.UtcNow).ToUniversalTime(),
                Payload = payloadDoc
            };
        }
    }
}

static class MiniTestSuite
{
    public static int RunAll()
    {
        var results = new List<(string Name, bool Pass, string? Err)>();
        void Run(string name, Action test)
        {
            try { test(); results.Add((name, true, null)); }
            catch (Exception ex) { results.Add((name, false, ex.Message)); }
        }

        Run("GenesisCreatesValidChain", Test_GenesisCreatesValidChain);
        Run("MineAndValidateBlock", Test_MineAndValidateBlock);
        Run("WorldState_Transfer", Test_WorldState_Transfer);
        Run("MerkleRootDeterminism", Test_MerkleRootDeterminism);
        Run("PowMatchesDifficulty", Test_PowMatchesDifficulty);
        Run("PersistenceRoundtrip", Test_PersistenceRoundtrip);
        Run("BadNonceRejected", Test_BadNonceRejected);

        int passed = results.Count(r => r.Pass);
        int failed = results.Count - passed;
        foreach (var r in results)
            Console.WriteLine($"{(r.Pass ? "[PASS]" : "[FAIL]")} {r.Name}{(r.Err is null ? "" : " :: " + r.Err)}");

        Console.WriteLine($"Summary: {results.Count} tests, {passed} passed, {failed} failed");
        return failed == 0 ? 0 : 1;
    }

    static void True(bool cond, string msg) { if (!cond) throw new Exception(msg); }
    static void Eq<T>(T exp, T act, string msg)
    {
        if (!EqualityComparer<T>.Default.Equals(exp, act))
            throw new Exception($"{msg} (expected: {exp}, actual: {act})");
    }

    static void Test_GenesisCreatesValidChain()
    {
        var c = new Blockchain();
        c.CreateGenesis();
        True(c.Chain.Count == 1, "Genesis block missing");
        True(c.IsValid(), "Chain should be valid after genesis");
    }

    static void Test_MineAndValidateBlock()
    {
        var c = new Blockchain();
        c.CreateGenesis();
        c.State.Accounts["A"] = 100_000; 
        var pool = new Mempool();
        var tx = new Transaction
        {
            Type = TransactionType.Fee,
            SenderPubKey = "A",
            Nonce = 0,
            TimestampUtc = new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc)
        };
        pool.Add(tx);
        var b = MinerService.MineNextBlock(c, pool);
        True(c.IsValid(), "Chain invalid after mined block");
        Eq(1, b.Index, "First mined block index should be 1");
    }

    static void Test_WorldState_Transfer()
    {
        var ws = new WorldState { FixedFeeMinor = 0 };
        ws.Accounts["S"] = 10_000;
        var tx = new Transaction
        {
            Type = TransactionType.Transfer,
            SenderPubKey = "S",
            Nonce = 0,
            TimestampUtc = new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            Payload = JsonDocument.Parse("{\"to\":\"R\",\"amountMinor\":5000}")
        };
        ws.Apply(tx, 0, DateTime.UtcNow);
        Eq(5_000L, ws.Accounts["S"], "Sender balance after transfer");
        Eq(5_000L, ws.Accounts["R"], "Receiver balance after transfer");
        Eq(0L, ws.Nonces["S"], "Nonce should advance to 0");
    }

    static void Test_MerkleRootDeterminism()
    {
        var t1 = new Transaction { Type = TransactionType.Fee, SenderPubKey = "X", Nonce = 0, TimestampUtc = new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc) };
        var t2 = new Transaction { Type = TransactionType.Fee, SenderPubKey = "Y", Nonce = 0, TimestampUtc = new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc) };
        var b = new Block { Index = 1, PreviousHash = "0", Difficulty = 1, Transactions = new List<Transaction> { t1, t2 } };
        var r1 = b.ComputeMerkleRoot();
        var r2 = b.ComputeMerkleRoot();
        Eq(r1, r2, "Merkle root must be deterministic");
    }

    static void Test_PowMatchesDifficulty()
    {
        var b = new Block { Index = 1, PreviousHash = "0", Difficulty = 2, Transactions = new List<Transaction>() };
        PowMiner.Mine(b);
        True(b.Hash.StartsWith("00", StringComparison.Ordinal), "Hash must start with 00 for difficulty 2");
    }

    static void Test_PersistenceRoundtrip()
    {
        var path = Path.Combine(Path.GetTempPath(), "minichain_test_" + Guid.NewGuid().ToString("N") + ".json");
        var storage = new FileChainStorage(path);

        var c = new Blockchain();
        c.CreateGenesis();
        c.State.Accounts["A"] = 100_000;
        var pool = new Mempool();
        pool.Add(new Transaction { Type = TransactionType.Fee, SenderPubKey = "A", Nonce = 0, TimestampUtc = new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc) });
        MinerService.MineNextBlock(c, pool);

        c.SaveTo(storage);

        var c2 = new Blockchain();
        c2.LoadFrom(storage);
        try { File.Delete(path); } catch { }

        True(c2.IsValid(), "Loaded chain should be valid");
        Eq(c.Chain.Count, c2.Chain.Count, "Height after load");
    }

    static void Test_BadNonceRejected()
    {
        var c = new Blockchain();
        c.CreateGenesis();
        c.State.Accounts["A"] = 100_000;

        var bad = new Transaction { Type = TransactionType.Fee, SenderPubKey = "A", Nonce = 2, TimestampUtc = new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc) };
        var b = new Block { Index = 1, PreviousHash = c.Latest.Hash, Difficulty = c.Difficulty, Transactions = new List<Transaction> { bad } };
        PowMiner.Mine(b);

        var threw = false;
        try { c.AddBlock(b); } catch { threw = true; }
        True(threw, "Block with bad nonce must be rejected");
    }
}


internal static class Program
{
    public static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        if (args.Contains("--test") || args.Contains("-t") || args.Contains("--selftest"))
            return MiniTestSuite.RunAll();

        var chain = new Blockchain();
        var storage = new FileChainStorage("data/blockchain.json");
        try { chain.LoadFrom(storage); }
        catch (FileNotFoundException) { chain.CreateGenesis(); chain.SaveTo(storage); }

        chain.State.FixedFeeMinor = 0;           
        chain.State.Accounts["demo"] = 1_000_000; 
        chain.SaveTo(storage);                   

        var pool = new Mempool();
        var app = Api.Build(args, chain, pool, storage);
        app.Run("http://localhost:5088");
        return 0;
    }
}

