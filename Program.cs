using Microsoft.Data.SqlClient;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

// Allow the Angular dev server to call this API from the browser.
builder.Services.AddCors(options =>
    options.AddDefaultPolicy(policy =>
        policy.WithOrigins("http://localhost:4200").AllowAnyHeader().AllowAnyMethod()));

var app = builder.Build();

app.UseCors();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

app.MapGet("/weatherforecast", () =>
{
    var forecast =  Enumerable.Range(1, 5).Select(index =>
        new WeatherForecast
        (
            DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            Random.Shared.Next(-20, 55),
            summaries[Random.Shared.Next(summaries.Length)]
        ))
        .ToArray();
    return forecast;
})
.WithName("GetWeatherForecast");

// Connection check: front -> back -> SQL Server.
app.MapGet("/api/health", async (IConfiguration config, ILogger<Program> logger) =>
{
    try
    {
        await using var connection = new SqlConnection(config.GetConnectionString("DefaultConnection"));
        await connection.OpenAsync();

        await using var command = new SqlCommand("SELECT DB_NAME()", connection);
        var database = (string?)await command.ExecuteScalarAsync();

        return Results.Ok(new { status = "connected", database });
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Database connection failed");
        return Results.Problem("Cannot connect to the database", statusCode: StatusCodes.Status503ServiceUnavailable);
    }
})
.WithName("GetHealth");

app.Run();

record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}
