using Microsoft.Data.SqlClient;

namespace Shop.Api.Data;

public interface IOrderRepository
{
    IEnumerable<string> QueryByCustomer(string customer);
}

public class OrderRepository : IOrderRepository
{
    private readonly SqlConnection _connection = new SqlConnection("Server=db;Database=shop");

    public IEnumerable<string> QueryByCustomer(string customer)
    {
        var sql = "SELECT id FROM Orders WHERE Customer = '" + customer + "'";
        using var command = new SqlCommand(sql, _connection);
        return new List<string>();
    }
}
