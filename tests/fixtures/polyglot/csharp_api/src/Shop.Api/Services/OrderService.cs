using Shop.Api.Data;

namespace Shop.Api.Services;

public interface IOrderService
{
    IEnumerable<string> FindByCustomer(string customer);
}

public class OrderService : IOrderService
{
    private readonly IOrderRepository _repository;

    public OrderService(IOrderRepository repository)
    {
        _repository = repository;
    }

    public IEnumerable<string> FindByCustomer(string customer)
    {
        var normalized = customer.Trim();
        return _repository.QueryByCustomer(normalized);
    }
}
