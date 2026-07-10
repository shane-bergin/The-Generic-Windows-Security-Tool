using TGWST.Core.Network.Capture;

namespace TGWST.Tests;

public sealed class IpHelperPollerTests
{
    [Fact]
    public void ValidateRowCount_AcceptsRowsWithinBuffer()
    {
        IpHelperPoller.ValidateRowCount(rowCount: 3, headerSize: 4, rowSize: 24, bufferSize: 76, tableName: "TCP");
    }

    [Fact]
    public void ValidateRowCount_RejectsNativeRowCountBeyondBuffer()
    {
        Assert.Throws<InvalidDataException>(() =>
            IpHelperPoller.ValidateRowCount(rowCount: uint.MaxValue, headerSize: 4, rowSize: 24, bufferSize: 4096, tableName: "TCP"));
    }

    [Fact]
    public void ValidateRowCount_RejectsTruncatedHeader()
    {
        Assert.Throws<InvalidDataException>(() =>
            IpHelperPoller.ValidateRowCount(rowCount: 0, headerSize: 4, rowSize: 12, bufferSize: 3, tableName: "UDP"));
    }
}
