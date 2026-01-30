using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Data.Sqlite;

namespace TGWST.Core.Network
{
    /// <summary>
    /// SQLite-based persistent storage for network flow records.
    /// Stores historical flow data for analysis and reporting.
    /// </summary>
    public sealed class FlowRecordStore : IDisposable
    {
        private readonly string _dbPath;
        private readonly SqliteConnection _connection;
        private bool _disposed;

        public FlowRecordStore(string? basePath = null)
        {
            var root = basePath ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "TGWST", "Network");
            Directory.CreateDirectory(root);

            _dbPath = Path.Combine(root, "flows.db");
            _connection = new SqliteConnection($"Data Source={_dbPath}");
            _connection.Open();

            // Enable WAL mode for better concurrent access
            using var walCmd = _connection.CreateCommand();
            walCmd.CommandText = "PRAGMA journal_mode=WAL;";
            walCmd.ExecuteNonQuery();

            using var busyCmd = _connection.CreateCommand();
            busyCmd.CommandText = "PRAGMA busy_timeout=2000;";
            busyCmd.ExecuteNonQuery();

            InitializeSchema();
        }

        private void InitializeSchema()
        {
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = @"
                CREATE TABLE IF NOT EXISTS flows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    flow_id TEXT NOT NULL,
                    process_id INTEGER,
                    process_name TEXT,
                    process_path TEXT,
                    process_signer TEXT,
                    protocol TEXT NOT NULL,
                    local_address TEXT,
                    local_port INTEGER,
                    remote_address TEXT,
                    remote_port INTEGER,
                    remote_hostname TEXT,
                    remote_country TEXT,
                    bytes_sent INTEGER DEFAULT 0,
                    bytes_received INTEGER DEFAULT 0,
                    packets_sent INTEGER DEFAULT 0,
                    packets_received INTEGER DEFAULT 0,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    matched_rule TEXT,
                    action TEXT DEFAULT 'Allow',
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_flows_process ON flows(process_name);
                CREATE INDEX IF NOT EXISTS idx_flows_remote ON flows(remote_address, remote_port);
                CREATE INDEX IF NOT EXISTS idx_flows_time ON flows(first_seen);
                CREATE INDEX IF NOT EXISTS idx_flows_action ON flows(action);

                CREATE TABLE IF NOT EXISTS process_totals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    process_name TEXT NOT NULL,
                    date TEXT NOT NULL,
                    bytes_sent INTEGER DEFAULT 0,
                    bytes_received INTEGER DEFAULT 0,
                    connection_count INTEGER DEFAULT 0,
                    UNIQUE(process_name, date)
                );

                CREATE INDEX IF NOT EXISTS idx_process_totals_date ON process_totals(date);
            ";
            cmd.ExecuteNonQuery();
        }

        /// <summary>
        /// Append a flow record to the database.
        /// </summary>
        public void Append(FlowRecord flow)
        {
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = @"
                INSERT INTO flows (
                    flow_id, process_id, process_name, process_path, process_signer,
                    protocol, local_address, local_port, remote_address, remote_port,
                    remote_hostname, remote_country, bytes_sent, bytes_received,
                    packets_sent, packets_received, first_seen, last_seen,
                    matched_rule, action
                ) VALUES (
                    @flowId, @pid, @pname, @ppath, @psigner,
                    @proto, @laddr, @lport, @raddr, @rport,
                    @rhost, @rcountry, @sent, @recv,
                    @psent, @precv, @first, @last,
                    @rule, @action
                )
            ";

            cmd.Parameters.AddWithValue("@flowId", flow.FlowId);
            cmd.Parameters.AddWithValue("@pid", flow.ProcessId);
            cmd.Parameters.AddWithValue("@pname", flow.ProcessName);
            cmd.Parameters.AddWithValue("@ppath", flow.ProcessPath ?? "");
            cmd.Parameters.AddWithValue("@psigner", (object?)flow.ProcessSigner ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@proto", flow.Protocol);
            cmd.Parameters.AddWithValue("@laddr", flow.LocalAddress);
            cmd.Parameters.AddWithValue("@lport", flow.LocalPort);
            cmd.Parameters.AddWithValue("@raddr", flow.RemoteAddress);
            cmd.Parameters.AddWithValue("@rport", flow.RemotePort);
            cmd.Parameters.AddWithValue("@rhost", (object?)flow.RemoteHostname ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@rcountry", (object?)flow.RemoteCountry ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@sent", flow.BytesSent);
            cmd.Parameters.AddWithValue("@recv", flow.BytesReceived);
            cmd.Parameters.AddWithValue("@psent", flow.PacketsSent);
            cmd.Parameters.AddWithValue("@precv", flow.PacketsReceived);
            cmd.Parameters.AddWithValue("@first", flow.FirstSeen.ToString("O"));
            cmd.Parameters.AddWithValue("@last", flow.LastSeen.ToString("O"));
            cmd.Parameters.AddWithValue("@rule", (object?)flow.MatchedRuleName ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@action", flow.Action.ToString());

            cmd.ExecuteNonQuery();
        }

        /// <summary>
        /// Append multiple flow records in a single transaction.
        /// </summary>
        public void AppendBatch(IEnumerable<FlowRecord> flows)
        {
            using var transaction = _connection.BeginTransaction();
            try
            {
                foreach (var flow in flows)
                {
                    Append(flow);
                }
                transaction.Commit();
            }
            catch
            {
                transaction.Rollback();
                throw;
            }
        }

        /// <summary>
        /// Update process daily totals for aggregated reporting.
        /// </summary>
        public void UpdateProcessTotals(string processName, DateTime date, long bytesSent, long bytesReceived, int connectionDelta = 1)
        {
            var dateStr = date.ToString("yyyy-MM-dd");

            using var cmd = _connection.CreateCommand();
            cmd.CommandText = @"
                INSERT INTO process_totals (process_name, date, bytes_sent, bytes_received, connection_count)
                VALUES (@name, @date, @sent, @recv, @count)
                ON CONFLICT(process_name, date) DO UPDATE SET
                    bytes_sent = bytes_sent + @sent,
                    bytes_received = bytes_received + @recv,
                    connection_count = connection_count + @count
            ";

            cmd.Parameters.AddWithValue("@name", processName);
            cmd.Parameters.AddWithValue("@date", dateStr);
            cmd.Parameters.AddWithValue("@sent", bytesSent);
            cmd.Parameters.AddWithValue("@recv", bytesReceived);
            cmd.Parameters.AddWithValue("@count", connectionDelta);

            cmd.ExecuteNonQuery();
        }

        /// <summary>
        /// Get historical per-process bandwidth totals since a given date.
        /// </summary>
        public IEnumerable<ProcessBandwidth> GetHistoricalProcessTotals(DateTime since)
        {
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = @"
                SELECT process_name, SUM(bytes_sent), SUM(bytes_received), SUM(connection_count)
                FROM process_totals
                WHERE date >= @since
                GROUP BY process_name
                ORDER BY SUM(bytes_sent) + SUM(bytes_received) DESC
            ";
            cmd.Parameters.AddWithValue("@since", since.ToString("yyyy-MM-dd"));

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                yield return new ProcessBandwidth
                {
                    ProcessName = reader.GetString(0),
                    BytesSent = reader.GetInt64(1),
                    BytesReceived = reader.GetInt64(2),
                    ConnectionCount = reader.GetInt32(3)
                };
            }
        }

        /// <summary>
        /// Get flow records for a specific process within a time range.
        /// </summary>
        public IEnumerable<FlowRecord> GetFlowsByProcess(string processName, DateTime since, int limit = 100)
        {
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = @"
                SELECT flow_id, process_id, process_name, process_path, process_signer,
                       protocol, local_address, local_port, remote_address, remote_port,
                       remote_hostname, remote_country, bytes_sent, bytes_received,
                       packets_sent, packets_received, first_seen, last_seen,
                       matched_rule, action
                FROM flows
                WHERE process_name = @name AND first_seen >= @since
                ORDER BY first_seen DESC
                LIMIT @limit
            ";
            cmd.Parameters.AddWithValue("@name", processName);
            cmd.Parameters.AddWithValue("@since", since.ToString("O"));
            cmd.Parameters.AddWithValue("@limit", limit);

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                yield return ReadFlowRecord(reader);
            }
        }

        /// <summary>
        /// Get recent flow records within a time range.
        /// </summary>
        public IEnumerable<FlowRecord> GetRecentFlows(DateTime since, int limit = 500)
        {
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = @"
                SELECT flow_id, process_id, process_name, process_path, process_signer,
                       protocol, local_address, local_port, remote_address, remote_port,
                       remote_hostname, remote_country, bytes_sent, bytes_received,
                       packets_sent, packets_received, first_seen, last_seen,
                       matched_rule, action
                FROM flows
                WHERE first_seen >= @since
                ORDER BY first_seen DESC
                LIMIT @limit
            ";
            cmd.Parameters.AddWithValue("@since", since.ToString("O"));
            cmd.Parameters.AddWithValue("@limit", limit);

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                yield return ReadFlowRecord(reader);
            }
        }

        /// <summary>
        /// Get blocked flows within a time range.
        /// </summary>
        public IEnumerable<FlowRecord> GetBlockedFlows(DateTime since, int limit = 100)
        {
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = @"
                SELECT flow_id, process_id, process_name, process_path, process_signer,
                       protocol, local_address, local_port, remote_address, remote_port,
                       remote_hostname, remote_country, bytes_sent, bytes_received,
                       packets_sent, packets_received, first_seen, last_seen,
                       matched_rule, action
                FROM flows
                WHERE action IN ('Block', 'Drop') AND first_seen >= @since
                ORDER BY first_seen DESC
                LIMIT @limit
            ";
            cmd.Parameters.AddWithValue("@since", since.ToString("O"));
            cmd.Parameters.AddWithValue("@limit", limit);

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                yield return ReadFlowRecord(reader);
            }
        }

        /// <summary>
        /// Prune flow records older than the specified date.
        /// </summary>
        public int PruneOldRecords(DateTime olderThan)
        {
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = @"
                DELETE FROM flows WHERE first_seen < @date;
                DELETE FROM process_totals WHERE date < @dateStr;
            ";
            cmd.Parameters.AddWithValue("@date", olderThan.ToString("O"));
            cmd.Parameters.AddWithValue("@dateStr", olderThan.ToString("yyyy-MM-dd"));

            return cmd.ExecuteNonQuery();
        }

        /// <summary>
        /// Get total storage statistics.
        /// </summary>
        public (long FlowCount, long TotalBytes, DateTime? OldestRecord) GetStats()
        {
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = @"
                SELECT COUNT(*), COALESCE(SUM(bytes_sent + bytes_received), 0), MIN(first_seen)
                FROM flows
            ";

            using var reader = cmd.ExecuteReader();
            if (reader.Read())
            {
                var count = reader.GetInt64(0);
                var bytes = reader.GetInt64(1);
                var oldest = reader.IsDBNull(2) ? (DateTime?)null : DateTime.Parse(reader.GetString(2));
                return (count, bytes, oldest);
            }

            return (0, 0, null);
        }

        private static FlowRecord ReadFlowRecord(SqliteDataReader reader)
        {
            return new FlowRecord
            {
                FlowId = reader.GetString(0),
                ProcessId = reader.GetInt32(1),
                ProcessName = reader.GetString(2),
                ProcessPath = reader.GetString(3),
                ProcessSigner = reader.IsDBNull(4) ? null : reader.GetString(4),
                Protocol = reader.GetString(5),
                LocalAddress = reader.GetString(6),
                LocalPort = reader.GetInt32(7),
                RemoteAddress = reader.GetString(8),
                RemotePort = reader.GetInt32(9),
                RemoteHostname = reader.IsDBNull(10) ? null : reader.GetString(10),
                RemoteCountry = reader.IsDBNull(11) ? null : reader.GetString(11),
                BytesSent = reader.GetInt64(12),
                BytesReceived = reader.GetInt64(13),
                PacketsSent = reader.GetInt64(14),
                PacketsReceived = reader.GetInt64(15),
                FirstSeen = DateTime.Parse(reader.GetString(16)),
                LastSeen = DateTime.Parse(reader.GetString(17)),
                MatchedRuleName = reader.IsDBNull(18) ? null : reader.GetString(18),
                Action = Enum.Parse<FlowAction>(reader.GetString(19))
            };
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            _connection.Close();
            _connection.Dispose();
        }
    }
}
