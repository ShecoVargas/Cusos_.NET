using Microsoft.AspNetCore.Mvc;
using BankAPI.Services;
using BankAPI.Data.BankModels;
using Microsoft.AspNetCore.Authorization;

namespace BankAPI.Controllers;

[Authorize]
[ApiController]
[Route("api/[controller]")]
public class ClientController : ControllerBase
{
    private readonly ClientService _service;
    public ClientController(ClientService service)
    {
        _service = service;
    }

    [HttpGet("getall")]
    public async Task<IEnumerable<Client>> Get()
    {
        return await _service.GetAll();
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<Client>> GetById(int id)
    {
        var Client = await _service.GetById(id);

        if (Client == null)
            return ClientNotFound(id);

        return Client;
    }
    
    [Authorize(Policy = "SuperAdmin")]
    [HttpPost("create")]
    public async Task<IActionResult> Create(Client client)
    {
        var newClient = await _service.Create(client);
    
        return CreatedAtAction(nameof(GetById), new { id = client.Id}, client);
    }

    [Authorize(Policy = "SuperAdmin")]
    [HttpPut("update/{id}")]
    public async Task<IActionResult> Update(int id, Client client)
    {
        if(id != client.Id)
            return BadRequest(new { message = $"El ID({id}) de la IRL no coincide con el ID({client.Id}) del cuerpo del cuerpo de la solicitud."});
        
        var clientToUpdate = await _service.GetById(id);

        if(clientToUpdate is not null)
        {
            await _service.Update(id, client);
            return NoContent();
        }
        else
        {
            return ClientNotFound(id);
        }
    }

    [Authorize(Policy = "SuperAdmin")]
    [HttpDelete("delete/{id}")]
    public async Task<IActionResult> Delete(int id)
    {
       var clientToDelete = await _service.GetById(id);

        if(clientToDelete is not null)
        {
            await _service.Delete(id);
            return Ok();
        }
        else
        {
            return ClientNotFound(id);
        }

    }

    public NotFoundObjectResult ClientNotFound(int id)
    {
        return NotFound(new { message = $"El cliente con ID = {id} no existe"});
    }
}