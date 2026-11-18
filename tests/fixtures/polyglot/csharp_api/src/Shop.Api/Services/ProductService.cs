using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;

namespace Shop.Api.Services;

public interface IProductService
{
    string Describe(string name);
}

public class ProductService : IProductService
{
    public string Describe(string name)
    {
        return $"Product {name}";
    }

    // VULNERABLE: BinaryFormatter is unsafe for any untrusted payload.
    public object Load(Stream payload)
    {
        var formatter = new BinaryFormatter();
        return formatter.Deserialize(payload);
    }

    // VULNERABLE: weak hash.
    public byte[] Fingerprint(byte[] data) => MD5.Create().ComputeHash(data);

    public HttpClient InsecureClient()
    {
        var handler = new HttpClientHandler();
        // VULNERABLE: certificate validation disabled.
        handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;
        return new HttpClient(handler);
    }
}
