using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

// Allow the Angular dev server to call this API from the browser, sending the session cookie.
builder.Services.AddCors(options =>
    options.AddDefaultPolicy(policy =>
        policy.WithOrigins("http://localhost:4200").AllowAnyHeader().AllowAnyMethod().AllowCredentials()));

// Session: an encrypted, HttpOnly cookie set at login. JavaScript cannot read it, and SameSite=Strict
// keeps other sites from sending it, which also protects the API from cross-site request forgery.
builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "trading_session";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest; // Always use HTTPS in production.
        options.ExpireTimeSpan = TimeSpan.FromDays(7);
        options.SlidingExpiration = true;
        // An API answers 401/403 instead of redirecting to a login page.
        options.Events.OnRedirectToLogin = context =>
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        };
        options.Events.OnRedirectToAccessDenied = context =>
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        };
        // A deleted account's sessions stop working at once, on every device, not only in the browser that deleted it.
        options.Events.OnValidatePrincipal = async context =>
        {
            if (!int.TryParse(context.Principal?.FindFirstValue(ClaimTypes.NameIdentifier), out var userId))
            {
                context.RejectPrincipal();
                return;
            }
            try
            {
                var config = context.HttpContext.RequestServices.GetRequiredService<IConfiguration>();
                await using var connection = new SqlConnection(config.GetConnectionString("DefaultConnection"));
                await connection.OpenAsync();
                await using var command = new SqlCommand(
                    "SELECT 1 FROM USERS WHERE user_id = @userId AND deleted_at IS NULL", connection);
                command.Parameters.AddWithValue("@userId", userId);
                if (await command.ExecuteScalarAsync() is null)
                {
                    context.RejectPrincipal();
                    await context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                }
            }
            catch (SqlException)
            {
                // Keep the session; the endpoint itself reports that the database cannot be reached.
            }
        };
    });
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseCors();

// Card photos sellers upload, served at /uploads/... (the folder is not committed to git).
const string UploadsFolder = "uploads";
// Files only some users may see, such as payment slips. Never served as static files (also not committed to git).
const string PrivateFolder = "private";
var uploadsPath = Path.Combine(app.Environment.ContentRootPath, UploadsFolder);
Directory.CreateDirectory(uploadsPath);
app.UseStaticFiles(new StaticFileOptions
{
    FileProvider = new Microsoft.Extensions.FileProviders.PhysicalFileProvider(uploadsPath),
    RequestPath = $"/{UploadsFolder}",
});

app.UseAuthentication();
app.UseAuthorization();

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

var passwordHasher = new PasswordHasher<string>();
// Verified when the username is unknown, so both failures take about the same time.
var unknownUserHash = passwordHasher.HashPassword(string.Empty, Guid.NewGuid().ToString());

app.MapPost("/api/auth/login", async (LoginRequest request, HttpContext http, IConfiguration config, ILogger<Program> logger) =>
{
    if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrEmpty(request.Password))
    {
        return Results.BadRequest(new { message = "Username and password are required" });
    }

    try
    {
        await using var connection = new SqlConnection(config.GetConnectionString("DefaultConnection"));
        await connection.OpenAsync();

        await using var command = new SqlCommand(
            "SELECT user_id, password FROM USERS WHERE username = @username",
            connection);
        command.Parameters.AddWithValue("@username", request.Username);

        int? userId = null;
        var storedHash = unknownUserHash;
        await using (var reader = await command.ExecuteReaderAsync())
        {
            if (await reader.ReadAsync())
            {
                userId = reader.GetInt32(0);
                storedHash = reader.GetString(1);
            }
        }

        var verification = passwordHasher.VerifyHashedPassword(string.Empty, storedHash, request.Password);
        var profile = userId is int id && verification != PasswordVerificationResult.Failed
            ? await LoadProfileAsync(connection, id)
            : null;
        if (profile is null)
        {
            return Results.Json(new { message = "Incorrect username or password" }, statusCode: StatusCodes.Status401Unauthorized);
        }

        var identity = new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, profile.UserId.ToString()),
                new Claim(ClaimTypes.Name, profile.Username),
            ],
            CookieAuthenticationDefaults.AuthenticationScheme);
        await http.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity),
            new AuthenticationProperties { IsPersistent = true });

        return Results.Ok(profile);
    }
    catch (SqlException ex)
    {
        logger.LogError(ex, "Login failed because of a database error");
        return Results.Problem("Cannot connect to the database", statusCode: StatusCodes.Status503ServiceUnavailable);
    }
})
.WithName("Login");

app.MapPost("/api/auth/register", async (RegisterRequest request, IConfiguration config, ILogger<Program> logger) =>
{
    var name = request.Name?.Trim() ?? "";
    var surname = request.Surname?.Trim() ?? "";
    var username = request.Username?.Trim() ?? "";
    var email = request.Email?.Trim() ?? "";
    var password = request.Password ?? "";
    var phoneNumber = request.PhoneNumber?.Trim() ?? "";
    var address = request.Address?.Trim() ?? "";

    var validationError =
        username.Length == 0 || password.Length == 0 ? "Please fill in all required fields"
        : username.Length > 50 ? "Username must be 50 characters or fewer"
        : password.Length is < 8 or > 128 ? "Password must be 8 to 128 characters"
        : ProfileError(name, surname, email, phoneNumber, address);
    if (validationError is not null)
    {
        return Results.BadRequest(new { message = validationError });
    }

    try
    {
        await using var connection = new SqlConnection(config.GetConnectionString("DefaultConnection"));
        await connection.OpenAsync();

        await using var command = new SqlCommand(
            """
            INSERT INTO USERS (name, surname, username, email, password, phone_number, address)
            OUTPUT INSERTED.user_id
            VALUES (@name, @surname, @username, @email, @password, @phoneNumber, @address)
            """,
            connection);
        command.Parameters.AddWithValue("@name", name);
        command.Parameters.AddWithValue("@surname", surname);
        command.Parameters.AddWithValue("@username", username);
        command.Parameters.AddWithValue("@email", email);
        command.Parameters.AddWithValue("@password", passwordHasher.HashPassword(string.Empty, password));
        command.Parameters.AddWithValue("@phoneNumber", phoneNumber.Length == 0 ? DBNull.Value : phoneNumber);
        command.Parameters.AddWithValue("@address", address.Length == 0 ? DBNull.Value : address);

        var userId = (int)(await command.ExecuteScalarAsync())!;
        return Results.Created($"/api/users/{userId}", new { userId, username });
    }
    catch (SqlException ex) when (ex.Number is 2601 or 2627) // unique constraint violation
    {
        var message = ex.Message.Contains("UQ_USERS_email", StringComparison.OrdinalIgnoreCase)
            ? "This email is already registered"
            : "This username is already taken";
        return Results.Conflict(new { message });
    }
    catch (SqlException ex)
    {
        logger.LogError(ex, "Registration failed because of a database error");
        return Results.Problem("Cannot connect to the database", statusCode: StatusCodes.Status503ServiceUnavailable);
    }
})
.WithName("Register");

// The logged-in user, from the session cookie. 401 when there is no valid session.
app.MapGet("/api/auth/me", async (ClaimsPrincipal principal, HttpContext http, IConfiguration config, ILogger<Program> logger) =>
{
    if (!int.TryParse(principal.FindFirstValue(ClaimTypes.NameIdentifier), out var userId))
    {
        return Results.Unauthorized();
    }

    try
    {
        await using var connection = new SqlConnection(config.GetConnectionString("DefaultConnection"));
        await connection.OpenAsync();

        var profile = await LoadProfileAsync(connection, userId);
        if (profile is null)
        {
            // The account no longer exists, so the session is no longer valid.
            await http.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Results.Unauthorized();
        }
        return Results.Ok(profile);
    }
    catch (SqlException ex)
    {
        logger.LogError(ex, "Loading the session user failed because of a database error");
        return Results.Problem("Cannot connect to the database", statusCode: StatusCodes.Status503ServiceUnavailable);
    }
})
.RequireAuthorization()
.WithName("GetCurrentUser");

// Ends the session by removing the cookie. Safe to call without a session.
app.MapPost("/api/auth/logout", async (HttpContext http) =>
{
    await http.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.NoContent();
})
.WithName("Logout");

// A seller's public details, for their profile page. 404 when nobody has this username or the account was deleted.
app.MapGet("/api/users/{username}", (string username, IConfiguration config, ILogger<Program> logger) =>
    QueryAsync(config, logger, "Loading a public profile", async connection =>
    {
        await using var command = new SqlCommand(
            """
            SELECT user_id, name, surname, username, email, phone_number
            FROM USERS WHERE username = @username AND deleted_at IS NULL
            """,
            connection);
        command.Parameters.AddWithValue("@username", username);

        await using var reader = await command.ExecuteReaderAsync();
        if (!await reader.ReadAsync())
        {
            return Results.NotFound(new { message = "This seller does not exist" });
        }
        return Results.Ok(new PublicProfile(
            reader.GetInt32(0),
            reader.GetString(1),
            reader.GetString(2),
            reader.GetString(3),
            reader.GetString(4),
            reader.IsDBNull(5) ? null : reader.GetString(5)));
    }))
.RequireAuthorization()
.WithName("GetPublicProfile");

// Changes the logged-in user's own details. The username stays fixed because orders and reviews show it.
app.MapPut("/api/users/me", async (UpdateProfileRequest request, ClaimsPrincipal principal, IConfiguration config, ILogger<Program> logger) =>
{
    if (CurrentUserId(principal) is not int userId)
    {
        return Results.Unauthorized();
    }

    var name = request.Name?.Trim() ?? "";
    var surname = request.Surname?.Trim() ?? "";
    var email = request.Email?.Trim() ?? "";
    var phoneNumber = request.PhoneNumber?.Trim() ?? "";
    var address = request.Address?.Trim() ?? "";
    if (ProfileError(name, surname, email, phoneNumber, address) is string error)
    {
        return Results.BadRequest(new { message = error });
    }

    return await QueryAsync(config, logger, "Updating a profile", async connection =>
    {
        await using var command = new SqlCommand(
            """
            UPDATE USERS
            SET name = @name, surname = @surname, email = @email, phone_number = @phoneNumber, address = @address
            WHERE user_id = @userId AND deleted_at IS NULL
            """,
            connection);
        command.Parameters.AddWithValue("@userId", userId);
        command.Parameters.AddWithValue("@name", name);
        command.Parameters.AddWithValue("@surname", surname);
        command.Parameters.AddWithValue("@email", email);
        command.Parameters.AddWithValue("@phoneNumber", phoneNumber.Length == 0 ? DBNull.Value : phoneNumber);
        command.Parameters.AddWithValue("@address", address.Length == 0 ? DBNull.Value : address);

        try
        {
            if (await command.ExecuteNonQueryAsync() == 0)
            {
                return Results.Unauthorized();
            }
        }
        catch (SqlException ex) when (ex.Number is 2601 or 2627) // UQ_USERS_email
        {
            return Results.Conflict(new { message = "This email is already used by another account" });
        }
        return Results.Ok(await LoadProfileAsync(connection, userId));
    });
})
.RequireAuthorization()
.WithName("UpdateProfile");

// Deletes the logged-in user's account after they confirm with their password. Sign-in stops working at once,
// cards nobody has ordered are taken off sale, and the rest is removed 30 days later (PurgeDeletedAccountsAsync).
// Not allowed while one of their orders, as buyer or seller, is still pending or shipped: the other person still
// needs to reach them.
app.MapDelete("/api/users/me", async ([FromBody] DeleteAccountRequest request, HttpContext http, ClaimsPrincipal principal,
    IWebHostEnvironment env, IConfiguration config, ILogger<Program> logger) =>
{
    if (CurrentUserId(principal) is not int userId)
    {
        return Results.Unauthorized();
    }
    if (string.IsNullOrEmpty(request.Password))
    {
        return Results.BadRequest(new { message = "Please enter your password" });
    }

    return await QueryAsync(config, logger, "Deleting an account", async connection =>
    {
        await using (var check = new SqlCommand(
            "SELECT password FROM USERS WHERE user_id = @userId AND deleted_at IS NULL", connection))
        {
            check.Parameters.AddWithValue("@userId", userId);
            if (await check.ExecuteScalarAsync() is not string hash)
            {
                return Results.Unauthorized();
            }
            if (passwordHasher.VerifyHashedPassword(string.Empty, hash, request.Password) == PasswordVerificationResult.Failed)
            {
                return Results.BadRequest(new { message = "Incorrect password" });
            }
        }

        await using var transaction = (SqlTransaction)await connection.BeginTransactionAsync();

        // Takes the cards nobody has ordered off sale first. Someone buying one of them now waits for this
        // transaction and then fails, and an order placed just before is caught by the check below.
        var pictures = new List<string?>();
        await using (var remove = new SqlCommand(
            """
            DELETE FROM CARDS OUTPUT DELETED.card_picture
            WHERE seller_id = @userId AND NOT EXISTS (SELECT 1 FROM ORDERS o WHERE o.card_id = CARDS.card_id);
            """,
            connection,
            transaction))
        {
            remove.Parameters.AddWithValue("@userId", userId);
            await using var reader = await remove.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                pictures.Add(reader.IsDBNull(0) ? null : reader.GetString(0));
            }
        }

        await using (var open = new SqlCommand(
            """
            SELECT COUNT(*)
            FROM ORDERS o JOIN CARDS c ON c.card_id = o.card_id
            WHERE (o.user_id = @userId OR c.seller_id = @userId) AND o.order_status IN (N'pending', N'shipped')
            """,
            connection,
            transaction))
        {
            open.Parameters.AddWithValue("@userId", userId);
            if ((int)(await open.ExecuteScalarAsync())! > 0)
            {
                await transaction.RollbackAsync(); // puts the cards back on sale
                return Results.Conflict(new
                {
                    message = "You still have orders that are not finished. Wait until every order you bought or sold is received, then try again.",
                });
            }
        }

        await using (var mark = new SqlCommand(
            "UPDATE USERS SET deleted_at = SYSUTCDATETIME() WHERE user_id = @userId", connection, transaction))
        {
            mark.Parameters.AddWithValue("@userId", userId);
            await mark.ExecuteNonQueryAsync();
        }
        await transaction.CommitAsync();

        foreach (var picture in pictures)
        {
            DeletePicture(picture, env);
        }
        await http.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return Results.NoContent();
    });
})
.RequireAuthorization()
.WithName("DeleteAccount");

// Removes accounts deleted more than 30 days ago: once when the API starts, then every hour while it runs.
app.Lifetime.ApplicationStarted.Register(() => _ = Task.Run(async () =>
{
    var stopping = app.Lifetime.ApplicationStopping;
    using var timer = new PeriodicTimer(TimeSpan.FromHours(1));
    try
    {
        do
        {
            try
            {
                await PurgeDeletedAccountsAsync(app.Configuration, app.Environment, app.Logger);
            }
            catch (SqlException ex)
            {
                app.Logger.LogError(ex, "Removing deleted accounts failed because of a database error");
            }
        } while (await timer.WaitForNextTickAsync(stopping));
    }
    catch (OperationCanceledException)
    {
        // The API is shutting down.
    }
}));

// Searches the card catalog (the cards that may be sold) by card name, set or number.
// Returns at most `limit` cards (default 50, up to 100), sorted by name, so the add card form stays fast.
const string CatalogColumns =
    "catalog_id, card_name, set_name, card_number, card_type, rarity, card_stage, card_element, card_picture, reference_price";

app.MapGet("/api/catalog", async (string? search, int? limit, IConfiguration config, ILogger<Program> logger) =>
{
    var term = search?.Trim() ?? "";
    if (term.Length > 100)
    {
        return Results.BadRequest(new { message = "Search must be 100 characters or fewer" });
    }
    var take = Math.Clamp(limit ?? 50, 1, 100);

    try
    {
        await using var connection = new SqlConnection(config.GetConnectionString("DefaultConnection"));
        await connection.OpenAsync();

        await using var command = new SqlCommand(
            $"""
            SELECT TOP (@take) {CatalogColumns}
            FROM CARD_CATALOG
            WHERE @pattern IS NULL
               OR card_name LIKE @pattern ESCAPE '\'
               OR set_name LIKE @pattern ESCAPE '\'
               OR card_number LIKE @pattern ESCAPE '\'
            ORDER BY card_name, set_name, card_number
            """,
            connection);
        command.Parameters.AddWithValue("@take", take);
        command.Parameters.Add("@pattern", System.Data.SqlDbType.NVarChar, 210).Value =
            term.Length == 0 ? DBNull.Value : $"%{EscapeLike(term)}%";

        var cards = new List<CatalogCard>();
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            cards.Add(ReadCatalogCard(reader));
        }
        return Results.Ok(cards);
    }
    catch (SqlException ex)
    {
        logger.LogError(ex, "Searching the catalog failed because of a database error");
        return Results.Problem("Cannot connect to the database", statusCode: StatusCodes.Status503ServiceUnavailable);
    }
})
.RequireAuthorization()
.WithName("SearchCatalog");

app.MapGet("/api/catalog/{catalogId:int}", async (int catalogId, IConfiguration config, ILogger<Program> logger) =>
{
    try
    {
        await using var connection = new SqlConnection(config.GetConnectionString("DefaultConnection"));
        await connection.OpenAsync();

        await using var command = new SqlCommand(
            $"SELECT {CatalogColumns} FROM CARD_CATALOG WHERE catalog_id = @catalogId",
            connection);
        command.Parameters.AddWithValue("@catalogId", catalogId);

        await using var reader = await command.ExecuteReaderAsync();
        return await reader.ReadAsync()
            ? Results.Ok(ReadCatalogCard(reader))
            : Results.NotFound(new { message = "This card is not in the catalog" });
    }
    catch (SqlException ex)
    {
        logger.LogError(ex, "Loading a catalog card failed because of a database error");
        return Results.Problem("Cannot connect to the database", statusCode: StatusCodes.Status503ServiceUnavailable);
    }
})
.RequireAuthorization()
.WithName("GetCatalogCard");

// ---- Listings: a seller offering one catalog card (the CARDS table) ----

const int MaxDescriptionLength = 1000;
const long MaxPictureBytes = 5 * 1024 * 1024;
// Column order is what ReadListing expects.
const string ListingSelect =
    """
    SELECT c.card_id, c.catalog_id, k.card_name, u.username, k.card_type, k.rarity, k.reference_price,
           c.card_price, k.card_stage, c.card_picture, k.card_picture, k.card_element, c.card_description,
           CAST(CASE WHEN EXISTS (SELECT 1 FROM ORDERS o WHERE o.card_id = c.card_id) THEN 1 ELSE 0 END AS BIT) AS sold
    FROM CARDS c
    JOIN CARD_CATALOG k ON k.catalog_id = c.catalog_id
    JOIN USERS u ON u.user_id = c.seller_id
    """;

// All listings, newest first. With ?seller=username, only that seller's.
app.MapGet("/api/listings", async (string? seller, HttpRequest request, IConfiguration config, ILogger<Program> logger) =>
{
    try
    {
        await using var connection = new SqlConnection(config.GetConnectionString("DefaultConnection"));
        await connection.OpenAsync();

        await using var command = new SqlCommand(
            $"{ListingSelect} WHERE @seller IS NULL OR u.username = @seller ORDER BY c.card_id DESC",
            connection);
        command.Parameters.Add("@seller", System.Data.SqlDbType.NVarChar, 50).Value =
            string.IsNullOrWhiteSpace(seller) ? DBNull.Value : seller.Trim();

        var listings = new List<CardListing>();
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            listings.Add(ReadListing(reader, request));
        }
        return Results.Ok(listings);
    }
    catch (SqlException ex)
    {
        logger.LogError(ex, "Loading listings failed because of a database error");
        return Results.Problem("Cannot connect to the database", statusCode: StatusCodes.Status503ServiceUnavailable);
    }
})
.RequireAuthorization()
.WithName("GetListings");

app.MapGet("/api/listings/{cardId:int}", async (int cardId, HttpRequest request, IConfiguration config, ILogger<Program> logger) =>
{
    try
    {
        await using var connection = new SqlConnection(config.GetConnectionString("DefaultConnection"));
        await connection.OpenAsync();
        var listing = await LoadListingAsync(connection, cardId, request);
        return listing is null ? Results.NotFound(new { message = "This card is not for sale" }) : Results.Ok(listing);
    }
    catch (SqlException ex)
    {
        logger.LogError(ex, "Loading a listing failed because of a database error");
        return Results.Problem("Cannot connect to the database", statusCode: StatusCodes.Status503ServiceUnavailable);
    }
})
.RequireAuthorization()
.WithName("GetListing");

// Lists a catalog card for sale. multipart/form-data: catalogId, cardPrice, cardDescription (optional), photo (optional).
// The form is read by hand, so no antiforgery token is involved; the SameSite=Strict session cookie already
// keeps other sites from posting here.
app.MapPost("/api/listings", async (HttpRequest request, ClaimsPrincipal principal, IWebHostEnvironment env, IConfiguration config, ILogger<Program> logger) =>
{
    if (!int.TryParse(principal.FindFirstValue(ClaimTypes.NameIdentifier), out var sellerId))
    {
        return Results.Unauthorized();
    }
    if (!request.HasFormContentType)
    {
        return Results.BadRequest(new { message = "Send the card as a form" });
    }

    var form = await request.ReadFormAsync();
    var description = form["cardDescription"].ToString().Trim();
    var photo = form.Files.GetFile("photo");

    var hasCatalogId = int.TryParse(form["catalogId"], out var catalogId);
    var priceError = ListingPriceError(form["cardPrice"], out var price);
    var validationError =
        !hasCatalogId ? "Please choose a card from the catalog"
        : priceError is not null ? priceError
        : description.Length > MaxDescriptionLength ? $"Description must be {MaxDescriptionLength} characters or fewer"
        : photo is not null ? await PictureErrorAsync(photo)
        : null;
    if (validationError is not null)
    {
        return Results.BadRequest(new { message = validationError });
    }

    string? photoPath = null;
    try
    {
        await using var connection = new SqlConnection(config.GetConnectionString("DefaultConnection"));
        await connection.OpenAsync();

        // Only catalog cards can be sold.
        await using (var exists = new SqlCommand("SELECT 1 FROM CARD_CATALOG WHERE catalog_id = @catalogId", connection))
        {
            exists.Parameters.AddWithValue("@catalogId", catalogId);
            if (await exists.ExecuteScalarAsync() is null)
            {
                return Results.BadRequest(new { message = "This card is not in the catalog" });
            }
        }

        if (photo is not null)
        {
            photoPath = await SavePictureAsync(photo, env);
        }

        await using var command = new SqlCommand(
            """
            INSERT INTO CARDS (seller_id, catalog_id, card_price, card_picture, card_description)
            OUTPUT INSERTED.card_id
            VALUES (@sellerId, @catalogId, @price, @picture, @description)
            """,
            connection);
        command.Parameters.AddWithValue("@sellerId", sellerId);
        command.Parameters.AddWithValue("@catalogId", catalogId);
        command.Parameters.Add("@price", System.Data.SqlDbType.Decimal).Value = price;
        command.Parameters["@price"].Precision = 12;
        command.Parameters["@price"].Scale = 2;
        command.Parameters.AddWithValue("@picture", (object?)photoPath ?? DBNull.Value);
        command.Parameters.AddWithValue("@description", description.Length == 0 ? DBNull.Value : description);

        var cardId = (int)(await command.ExecuteScalarAsync())!;
        var listing = await LoadListingAsync(connection, cardId, request);
        return Results.Created($"/api/listings/{cardId}", listing);
    }
    catch (SqlException ex)
    {
        DeletePicture(photoPath, env);
        logger.LogError(ex, "Adding a listing failed because of a database error");
        return Results.Problem("Cannot connect to the database", statusCode: StatusCodes.Status503ServiceUnavailable);
    }
})
.RequireAuthorization()
.WithName("AddListing");

// Changes the price and description of the logged-in user's own listing.
app.MapPut("/api/listings/{cardId:int}", async (int cardId, UpdateListingRequest body, HttpRequest request, ClaimsPrincipal principal, IConfiguration config, ILogger<Program> logger) =>
{
    if (!int.TryParse(principal.FindFirstValue(ClaimTypes.NameIdentifier), out var sellerId))
    {
        return Results.Unauthorized();
    }

    var description = body.CardDescription?.Trim() ?? "";
    var priceError = ListingPriceError(body.CardPrice?.ToString(System.Globalization.CultureInfo.InvariantCulture), out var price);
    var validationError =
        priceError is not null ? priceError
        : description.Length > MaxDescriptionLength ? $"Description must be {MaxDescriptionLength} characters or fewer"
        : null;
    if (validationError is not null)
    {
        return Results.BadRequest(new { message = validationError });
    }

    try
    {
        await using var connection = new SqlConnection(config.GetConnectionString("DefaultConnection"));
        await connection.OpenAsync();

        await using var command = new SqlCommand(
            """
            UPDATE CARDS SET card_price = @price, card_description = @description
            WHERE card_id = @cardId AND seller_id = @sellerId
              AND NOT EXISTS (SELECT 1 FROM ORDERS o WHERE o.card_id = CARDS.card_id);
            SELECT @@ROWCOUNT, CAST(CASE WHEN EXISTS (SELECT 1 FROM ORDERS o JOIN CARDS c ON c.card_id = o.card_id
                WHERE o.card_id = @cardId AND c.seller_id = @sellerId) THEN 1 ELSE 0 END AS BIT);
            """,
            connection);
        command.Parameters.AddWithValue("@cardId", cardId);
        command.Parameters.AddWithValue("@sellerId", sellerId);
        command.Parameters.Add("@price", System.Data.SqlDbType.Decimal).Value = price;
        command.Parameters["@price"].Precision = 12;
        command.Parameters["@price"].Scale = 2;
        command.Parameters.AddWithValue("@description", description.Length == 0 ? DBNull.Value : description);

        int changed;
        bool sold;
        await using (var reader = await command.ExecuteReaderAsync())
        {
            await reader.ReadAsync();
            changed = reader.GetInt32(0);
            sold = reader.GetBoolean(1);
        }

        // Someone else's listing looks the same as a missing one. A sold card keeps the price the buyer paid.
        return changed > 0 ? Results.Ok(await LoadListingAsync(connection, cardId, request))
            : sold ? Results.Conflict(new { message = "This card has been sold, so it cannot be changed" })
            : Results.NotFound(new { message = "You have no such card for sale" });
    }
    catch (SqlException ex)
    {
        logger.LogError(ex, "Updating a listing failed because of a database error");
        return Results.Problem("Cannot connect to the database", statusCode: StatusCodes.Status503ServiceUnavailable);
    }
})
.RequireAuthorization()
.WithName("UpdateListing");

// Removes the logged-in user's own listing, unless someone has already ordered it.
app.MapDelete("/api/listings/{cardId:int}", async (int cardId, ClaimsPrincipal principal, IWebHostEnvironment env, IConfiguration config, ILogger<Program> logger) =>
{
    if (!int.TryParse(principal.FindFirstValue(ClaimTypes.NameIdentifier), out var sellerId))
    {
        return Results.Unauthorized();
    }

    try
    {
        await using var connection = new SqlConnection(config.GetConnectionString("DefaultConnection"));
        await connection.OpenAsync();

        await using var command = new SqlCommand(
            "DELETE FROM CARDS OUTPUT DELETED.card_picture WHERE card_id = @cardId AND seller_id = @sellerId",
            connection);
        command.Parameters.AddWithValue("@cardId", cardId);
        command.Parameters.AddWithValue("@sellerId", sellerId);

        await using var reader = await command.ExecuteReaderAsync();
        if (!await reader.ReadAsync())
        {
            return Results.NotFound(new { message = "You have no such card for sale" });
        }
        DeletePicture(reader.IsDBNull(0) ? null : reader.GetString(0), env);
        return Results.NoContent();
    }
    catch (SqlException ex) when (ex.Number == 547) // an order refers to this card
    {
        return Results.Conflict(new { message = "Someone has ordered this card, so it cannot be removed" });
    }
    catch (SqlException ex)
    {
        logger.LogError(ex, "Removing a listing failed because of a database error");
        return Results.Problem("Cannot connect to the database", statusCode: StatusCodes.Status503ServiceUnavailable);
    }
})
.RequireAuthorization()
.WithName("DeleteListing");

// ---- Orders: a buyer ordering one listing, paid by bank transfer with a payment slip ----
// pending -> shipped (the seller checked the slip and sent the card) -> received (the buyer confirmed it arrived).

const int MaxReviewLength = 500;
// Column order is what ReadReview expects; card_id (5) is for finding the card a review is about.
const string ReviewSelect =
    """
    SELECT r.review_id, r.order_id, rb.username, r.review_status, r.comment, o.card_id
    FROM REVIEWS r
    JOIN USERS rb ON rb.user_id = r.buyer_id
    JOIN ORDERS o ON o.order_id = r.order_id
    """;
// Column order is what ReadOrder and ReadSale expect.
const string OrderSelect =
    """
    SELECT o.order_id, o.card_id, b.username, o.order_status, o.order_price, o.payment_slip,
           b.name, b.surname, b.email, b.phone_number, b.address
    FROM ORDERS o
    JOIN USERS b ON b.user_id = o.user_id
    JOIN CARDS c ON c.card_id = o.card_id
    """;

// The logged-in user's orders, newest first.
app.MapGet("/api/orders/mine", async (ClaimsPrincipal principal, HttpRequest request, IConfiguration config, ILogger<Program> logger) =>
{
    if (CurrentUserId(principal) is not int userId)
    {
        return Results.Unauthorized();
    }
    return await QueryAsync(config, logger, "Loading orders", async connection =>
    {
        await using var command = new SqlCommand($"{OrderSelect} WHERE o.user_id = @userId ORDER BY o.order_id DESC", connection);
        command.Parameters.AddWithValue("@userId", userId);
        var orders = new List<Order>();
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            orders.Add(ReadOrder(reader, request));
        }
        return Results.Ok(orders);
    });
})
.RequireAuthorization()
.WithName("GetMyOrders");

// Orders for the logged-in user's cards, newest first, with the buyer's contact details and address for shipping.
app.MapGet("/api/orders/sales", async (ClaimsPrincipal principal, HttpRequest request, IConfiguration config, ILogger<Program> logger) =>
{
    if (CurrentUserId(principal) is not int userId)
    {
        return Results.Unauthorized();
    }
    return await QueryAsync(config, logger, "Loading sales", async connection =>
    {
        await using var command = new SqlCommand($"{OrderSelect} WHERE c.seller_id = @userId ORDER BY o.order_id DESC", connection);
        command.Parameters.AddWithValue("@userId", userId);
        var sales = new List<Sale>();
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            sales.Add(ReadSale(reader, request));
        }
        return Results.Ok(sales);
    });
})
.RequireAuthorization()
.WithName("GetMySales");

// Orders a card. multipart/form-data: cardId and slip (the payment slip picture, required).
// The price is the listing's price now, not one the browser sends.
app.MapPost("/api/orders", async (HttpRequest request, ClaimsPrincipal principal, IWebHostEnvironment env, IConfiguration config, ILogger<Program> logger) =>
{
    if (CurrentUserId(principal) is not int buyerId)
    {
        return Results.Unauthorized();
    }
    if (!request.HasFormContentType)
    {
        return Results.BadRequest(new { message = "Send the order as a form" });
    }

    var form = await request.ReadFormAsync();
    var slip = form.Files.GetFile("slip");
    if (!int.TryParse(form["cardId"], out var cardId))
    {
        return Results.BadRequest(new { message = "Please choose a card to buy" });
    }
    if (slip is null)
    {
        return Results.BadRequest(new { message = "Please attach your payment slip" });
    }
    if (await PictureErrorAsync(slip) is { } slipError)
    {
        return Results.BadRequest(new { message = slipError });
    }

    string? slipName = null;
    try
    {
        await using var connection = new SqlConnection(config.GetConnectionString("DefaultConnection"));
        await connection.OpenAsync();

        int sellerId;
        decimal price;
        await using (var card = new SqlCommand("SELECT seller_id, card_price FROM CARDS WHERE card_id = @cardId", connection))
        {
            card.Parameters.AddWithValue("@cardId", cardId);
            await using var reader = await card.ExecuteReaderAsync();
            if (!await reader.ReadAsync())
            {
                return Results.NotFound(new { message = "This card is not for sale" });
            }
            sellerId = reader.GetInt32(0);
            price = reader.GetDecimal(1);
        }
        if (sellerId == buyerId)
        {
            return Results.BadRequest(new { message = "You cannot buy your own card" });
        }

        slipName = await SaveFileAsync(slip, SlipFolder(env));
        await using var command = new SqlCommand(
            """
            INSERT INTO ORDERS (user_id, card_id, order_status, order_price, payment_slip)
            OUTPUT INSERTED.order_id
            VALUES (@buyerId, @cardId, N'pending', @price, @slip)
            """,
            connection);
        command.Parameters.AddWithValue("@buyerId", buyerId);
        command.Parameters.AddWithValue("@cardId", cardId);
        command.Parameters.Add("@price", System.Data.SqlDbType.Decimal).Value = price;
        command.Parameters["@price"].Precision = 12;
        command.Parameters["@price"].Scale = 2;
        command.Parameters.AddWithValue("@slip", $"slips/{slipName}");

        var orderId = (int)(await command.ExecuteScalarAsync())!;
        return Results.Created($"/api/orders/{orderId}", await LoadOrderAsync(connection, orderId, request));
    }
    catch (SqlException ex) when (ex.Number is 2601 or 2627) // UQ_ORDERS_card: someone ordered it first
    {
        DeleteSlip(slipName, env);
        return Results.Conflict(new { message = "Sorry, someone has already bought this card" });
    }
    catch (SqlException ex)
    {
        DeleteSlip(slipName, env);
        logger.LogError(ex, "Placing an order failed because of a database error");
        return Results.Problem("Cannot connect to the database", statusCode: StatusCodes.Status503ServiceUnavailable);
    }
})
.RequireAuthorization()
.WithName("PlaceOrder");

// The payment slip picture, for the order's buyer and the card's seller only.
app.MapGet("/api/orders/{orderId:int}/slip", async (int orderId, ClaimsPrincipal principal, IWebHostEnvironment env, IConfiguration config, ILogger<Program> logger) =>
{
    if (CurrentUserId(principal) is not int userId)
    {
        return Results.Unauthorized();
    }
    return await QueryAsync(config, logger, "Loading a payment slip", async connection =>
    {
        await using var command = new SqlCommand(
            """
            SELECT o.payment_slip FROM ORDERS o JOIN CARDS c ON c.card_id = o.card_id
            WHERE o.order_id = @orderId AND (o.user_id = @userId OR c.seller_id = @userId)
            """,
            connection);
        command.Parameters.AddWithValue("@orderId", orderId);
        command.Parameters.AddWithValue("@userId", userId);
        var path = await command.ExecuteScalarAsync() as string;
        var file = path is null ? null : Path.Combine(SlipFolder(env), Path.GetFileName(path));
        if (file is null || !File.Exists(file))
        {
            return Results.NotFound(new { message = "No payment slip for this order" });
        }
        var contentType = Path.GetExtension(file) switch { ".png" => "image/png", ".webp" => "image/webp", _ => "image/jpeg" };
        return Results.File(file, contentType);
    });
})
.RequireAuthorization()
.WithName("GetPaymentSlip");

// The seller checked the payment and sent the card.
app.MapPost("/api/orders/{orderId:int}/ship", (int orderId, ClaimsPrincipal principal, HttpRequest request, IConfiguration config, ILogger<Program> logger) =>
    ChangeOrderStatusAsync(orderId, principal, request, config, logger, asSeller: true, from: "pending", to: "shipped"))
.RequireAuthorization()
.WithName("ShipOrder");

// The buyer confirmed the card arrived, which unlocks the review.
app.MapPost("/api/orders/{orderId:int}/receive", (int orderId, ClaimsPrincipal principal, HttpRequest request, IConfiguration config, ILogger<Program> logger) =>
    ChangeOrderStatusAsync(orderId, principal, request, config, logger, asSeller: false, from: "shipped", to: "received"))
.RequireAuthorization()
.WithName("ReceiveOrder");

// ---- Reviews: one per order, written by the buyer once they have received the card ----

// Reviews on the logged-in user's own orders.
app.MapGet("/api/reviews/mine", async (ClaimsPrincipal principal, IConfiguration config, ILogger<Program> logger) =>
{
    if (CurrentUserId(principal) is not int userId)
    {
        return Results.Unauthorized();
    }
    return await QueryAsync(config, logger, "Loading reviews", async connection =>
    {
        await using var command = new SqlCommand(
            $"{ReviewSelect} WHERE r.buyer_id = @userId ORDER BY r.review_id DESC",
            connection);
        command.Parameters.AddWithValue("@userId", userId);
        var reviews = new List<Review>();
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            reviews.Add(ReadReview(reader));
        }
        return Results.Ok(reviews);
    });
})
.RequireAuthorization()
.WithName("GetMyReviews");

// Reviews buyers wrote on orders for this seller's cards, newest first, each with the card it was for.
app.MapGet("/api/reviews", async (string? seller, HttpRequest request, IConfiguration config, ILogger<Program> logger) =>
{
    if (string.IsNullOrWhiteSpace(seller))
    {
        return Results.BadRequest(new { message = "Say whose reviews to show" });
    }
    return await QueryAsync(config, logger, "Loading a seller's reviews", async connection =>
    {
        var found = new List<(Review Review, int CardId)>();
        await using (var command = new SqlCommand(
            $"""
            {ReviewSelect}
            JOIN CARDS c ON c.card_id = o.card_id
            JOIN USERS s ON s.user_id = c.seller_id
            WHERE s.username = @seller AND r.review_status = N'reviewed'
            ORDER BY r.review_id DESC
            """,
            connection))
        {
            command.Parameters.AddWithValue("@seller", seller.Trim());
            await using var reader = await command.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                found.Add((ReadReview(reader), reader.GetInt32(5)));
            }
        }

        var reviews = new List<SellerReview>();
        foreach (var (review, cardId) in found)
        {
            if (await LoadListingAsync(connection, cardId, request) is { } card)
            {
                reviews.Add(new SellerReview(review, card));
            }
        }
        return Results.Ok(reviews);
    });
})
.RequireAuthorization()
.WithName("GetSellerReviews");

// The buyer reviews a received order, once. JSON: { comment }.
app.MapPost("/api/orders/{orderId:int}/review", async (int orderId, AddReviewRequest body, ClaimsPrincipal principal, IConfiguration config, ILogger<Program> logger) =>
{
    if (CurrentUserId(principal) is not int userId)
    {
        return Results.Unauthorized();
    }
    var comment = body.Comment?.Trim() ?? "";
    if (comment.Length == 0)
    {
        return Results.BadRequest(new { message = "Please write your review" });
    }
    if (comment.Length > MaxReviewLength)
    {
        return Results.BadRequest(new { message = $"Your review must be {MaxReviewLength} characters or fewer" });
    }

    try
    {
        await using var connection = new SqlConnection(config.GetConnectionString("DefaultConnection"));
        await connection.OpenAsync();

        string? status;
        await using (var order = new SqlCommand("SELECT order_status FROM ORDERS WHERE order_id = @orderId AND user_id = @userId", connection))
        {
            order.Parameters.AddWithValue("@orderId", orderId);
            order.Parameters.AddWithValue("@userId", userId);
            status = await order.ExecuteScalarAsync() as string;
        }
        if (status is null)
        {
            return Results.NotFound(new { message = "You have no such order" });
        }
        if (status != "received")
        {
            return Results.Conflict(new { message = "Confirm receipt before reviewing this order" });
        }

        // A 'not_reviewed' row may already exist for the order; it becomes the review. A 'reviewed' one cannot change.
        await using var command = new SqlCommand(
            $"""
            UPDATE REVIEWS SET comment = @comment, review_status = N'reviewed'
            WHERE order_id = @orderId AND review_status = N'not_reviewed';
            IF @@ROWCOUNT = 0
                INSERT INTO REVIEWS (order_id, buyer_id, comment, review_status)
                VALUES (@orderId, @userId, @comment, N'reviewed');
            {ReviewSelect} WHERE r.order_id = @orderId;
            """,
            connection);
        command.Parameters.AddWithValue("@orderId", orderId);
        command.Parameters.AddWithValue("@userId", userId);
        command.Parameters.AddWithValue("@comment", comment);
        await using var reader = await command.ExecuteReaderAsync();
        await reader.ReadAsync();
        return Results.Created($"/api/orders/{orderId}/review", ReadReview(reader));
    }
    catch (SqlException ex) when (ex.Number is 2601 or 2627) // UQ_REVIEWS_order
    {
        return Results.Conflict(new { message = "This order has already been reviewed" });
    }
    catch (SqlException ex)
    {
        logger.LogError(ex, "Adding a review failed because of a database error");
        return Results.Problem("Cannot connect to the database", statusCode: StatusCodes.Status503ServiceUnavailable);
    }
})
.RequireAuthorization()
.WithName("AddReview");

app.Run();

static int? CurrentUserId(ClaimsPrincipal principal) =>
    int.TryParse(principal.FindFirstValue(ClaimTypes.NameIdentifier), out var id) ? id : null;

// Opens a connection and runs a read; a database error becomes a 503 like everywhere else.
static async Task<IResult> QueryAsync(IConfiguration config, ILogger logger, string what, Func<SqlConnection, Task<IResult>> run)
{
    try
    {
        await using var connection = new SqlConnection(config.GetConnectionString("DefaultConnection"));
        await connection.OpenAsync();
        return await run(connection);
    }
    catch (SqlException ex)
    {
        logger.LogError(ex, "{What} failed because of a database error", what);
        return Results.Problem("Cannot connect to the database", statusCode: StatusCodes.Status503ServiceUnavailable);
    }
}

// Moves an order one step on. Only the card's seller ships, and only the buyer confirms receipt.
static Task<IResult> ChangeOrderStatusAsync(int orderId, ClaimsPrincipal principal, HttpRequest request, IConfiguration config,
    ILogger logger, bool asSeller, string from, string to)
{
    if (CurrentUserId(principal) is not int userId)
    {
        return Task.FromResult(Results.Unauthorized());
    }
    return QueryAsync(config, logger, $"Marking an order as {to}", async connection =>
    {
        await using (var command = new SqlCommand(
            $"""
            SELECT o.order_status FROM ORDERS o JOIN CARDS c ON c.card_id = o.card_id
            WHERE o.order_id = @orderId AND {(asSeller ? "c.seller_id" : "o.user_id")} = @userId
            """,
            connection))
        {
            command.Parameters.AddWithValue("@orderId", orderId);
            command.Parameters.AddWithValue("@userId", userId);
            var status = await command.ExecuteScalarAsync() as string;
            if (status is null)
            {
                return Results.NotFound(new { message = "You have no such order" });
            }
            if (status != from)
            {
                return Results.Conflict(new { message = to == "shipped"
                    ? "This order has already been shipped"
                    : "This order cannot be marked as received yet" });
            }
        }

        await using (var update = new SqlCommand(
            "UPDATE ORDERS SET order_status = @to WHERE order_id = @orderId AND order_status = @from",
            connection))
        {
            update.Parameters.AddWithValue("@orderId", orderId);
            update.Parameters.AddWithValue("@from", from);
            update.Parameters.AddWithValue("@to", to);
            if (await update.ExecuteNonQueryAsync() == 0)
            {
                return Results.Conflict(new { message = "This order changed meanwhile. Please reload the page." });
            }
        }
        return Results.Ok(await LoadOrderAsync(connection, orderId, request));
    });
}

static async Task<Order?> LoadOrderAsync(SqlConnection connection, int orderId, HttpRequest request)
{
    await using var command = new SqlCommand($"{OrderSelect} WHERE o.order_id = @orderId", connection);
    command.Parameters.AddWithValue("@orderId", orderId);
    await using var reader = await command.ExecuteReaderAsync();
    return await reader.ReadAsync() ? ReadOrder(reader, request) : null;
}

static Order ReadOrder(SqlDataReader reader, HttpRequest request)
{
    var orderId = reader.GetInt32(0);
    return new Order(
        orderId,
        reader.GetInt32(1),
        reader.GetString(2),
        reader.GetString(3),
        reader.GetDecimal(4),
        // The slip is only sent through the slip endpoint, which checks who is asking.
        reader.IsDBNull(5) ? null : $"{request.Scheme}://{request.Host}/api/orders/{orderId}/slip");
}

static Sale ReadSale(SqlDataReader reader, HttpRequest request)
{
    string? Text(int i) => reader.IsDBNull(i) ? null : reader.GetString(i);
    var order = ReadOrder(reader, request);
    return new Sale(
        order.OrderId, order.CardId, order.BuyerName, order.OrderStatus, order.OrderPrice, order.PaymentSlip,
        new BuyerContact(reader.GetString(6), reader.GetString(7), reader.GetString(8), Text(9), Text(10)));
}

static Review ReadReview(SqlDataReader reader) =>
    new(reader.GetInt32(0), reader.GetInt32(1), reader.GetString(2), reader.GetString(3), reader.IsDBNull(4) ? "" : reader.GetString(4));

static void DeleteSlip(string? name, IWebHostEnvironment env)
{
    if (name is null)
    {
        return;
    }
    var file = Path.Combine(SlipFolder(env), Path.GetFileName(name));
    if (File.Exists(file))
    {
        File.Delete(file);
    }
}

// A listing joined with its catalog card and seller. card_picture is the seller's photo, or the catalog picture without one.
static async Task<CardListing?> LoadListingAsync(SqlConnection connection, int cardId, HttpRequest request)
{
    await using var command = new SqlCommand($"{ListingSelect} WHERE c.card_id = @cardId", connection);
    command.Parameters.AddWithValue("@cardId", cardId);
    await using var reader = await command.ExecuteReaderAsync();
    return await reader.ReadAsync() ? ReadListing(reader, request) : null;
}

static CardListing ReadListing(SqlDataReader reader, HttpRequest request)
{
    string? Text(int i) => reader.IsDBNull(i) ? null : reader.GetString(i);
    // Uploaded photos are stored as a path on this API; the browser needs the full address.
    var photo = Text(9);
    var picture = photo is null ? Text(10) : $"{request.Scheme}://{request.Host}{photo}";
    return new CardListing(
        reader.GetInt32(0),
        reader.GetInt32(1),
        reader.GetString(2),
        reader.GetString(3),
        reader.GetString(4),
        reader.GetString(5),
        reader.IsDBNull(6) ? null : reader.GetDecimal(6),
        reader.GetDecimal(7),
        Text(8),
        Text(11),
        picture,
        Text(12),
        reader.GetBoolean(13));
}

// The price must be a whole number of baht from 1 to the largest that fits DECIMAL(12,2).
static string? ListingPriceError(string? value, out decimal price)
{
    if (!decimal.TryParse(value, System.Globalization.NumberStyles.Number, System.Globalization.CultureInfo.InvariantCulture, out price))
    {
        return "Please enter your price";
    }
    return price is < 1 or > 9_999_999_999 || price != decimal.Truncate(price)
        ? "Price must be a whole number from 1 to 9,999,999,999"
        : null;
}

// JPG, PNG or WebP up to 5 MB, checked by the file's first bytes rather than the name the browser sent.
static async Task<string?> PictureErrorAsync(IFormFile file)
{
    if (file.Length == 0 || file.Length > MaxPictureBytes)
    {
        return "The picture must be 5 MB or smaller";
    }
    return await PictureExtensionAsync(file) is null ? "Please choose a JPG, PNG or WebP picture" : null;
}

static async Task<string?> PictureExtensionAsync(IFormFile file)
{
    var head = new byte[12];
    await using var stream = file.OpenReadStream();
    var read = await stream.ReadAtLeastAsync(head, head.Length, throwOnEndOfStream: false);
    if (read >= 3 && head[0] == 0xFF && head[1] == 0xD8 && head[2] == 0xFF) return ".jpg";
    if (read >= 8 && head.AsSpan(0, 8).SequenceEqual(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A })) return ".png";
    if (read >= 12 && head.AsSpan(0, 4).SequenceEqual("RIFF"u8) && head.AsSpan(8, 4).SequenceEqual("WEBP"u8)) return ".webp";
    return null;
}

// Saves an uploaded picture under uploads/listings with a random name and returns its path on this API.
static async Task<string> SavePictureAsync(IFormFile file, IWebHostEnvironment env) =>
    $"/{UploadsFolder}/listings/{await SaveFileAsync(file, Path.Combine(env.ContentRootPath, UploadsFolder, "listings"))}";

// Saves a picture in the folder with a random name and returns the name.
static async Task<string> SaveFileAsync(IFormFile file, string folder)
{
    var extension = await PictureExtensionAsync(file) ?? throw new InvalidOperationException("Not a picture");
    Directory.CreateDirectory(folder);
    var name = $"{Guid.NewGuid():N}{extension}";
    await using (var output = File.Create(Path.Combine(folder, name)))
    {
        await file.CopyToAsync(output);
    }
    return name;
}

// Payment slips are private: they live outside the public uploads folder and are only sent to the buyer and seller.
static string SlipFolder(IWebHostEnvironment env) => Path.Combine(env.ContentRootPath, PrivateFolder, "slips");

static void DeletePicture(string? path, IWebHostEnvironment env)
{
    if (path is null || !path.StartsWith($"/{UploadsFolder}/listings/", StringComparison.Ordinal))
    {
        return;
    }
    var file = Path.Combine(env.ContentRootPath, UploadsFolder, "listings", Path.GetFileName(path));
    if (File.Exists(file))
    {
        File.Delete(file);
    }
}

// LIKE treats %, _ and [ as wildcards; escape them so they match themselves.
static string EscapeLike(string value) =>
    value.Replace(@"\", @"\\").Replace("%", @"\%").Replace("_", @"\_").Replace("[", @"\[");

static CatalogCard ReadCatalogCard(SqlDataReader reader)
{
    string? Text(int i) => reader.IsDBNull(i) ? null : reader.GetString(i);
    return new CatalogCard(
        reader.GetInt32(0),
        reader.GetString(1),
        Text(2),
        Text(3),
        reader.GetString(4),
        reader.GetString(5),
        Text(6),
        Text(7),
        Text(8),
        reader.IsDBNull(9) ? null : reader.GetDecimal(9));
}

// The details a user enters at registration and may change later. Same limits as the USERS table.
static string? ProfileError(string name, string surname, string email, string phoneNumber, string address) =>
    name.Length == 0 || surname.Length == 0 || email.Length == 0 ? "Please fill in all required fields"
    : name.Length > 100 || surname.Length > 100 ? "Name and surname must be 100 characters or fewer"
    : email.Length > 255 || !IsValidEmail(email) ? "Please enter a valid email"
    : phoneNumber.Length > 20 ? "Phone number must be 20 characters or fewer"
    : address.Length > 500 ? "Address must be 500 characters or fewer"
    : null;

// Removes accounts deleted more than 30 days ago, with their activity, as the privacy policy promises: their cards,
// the orders they placed or received and the reviews on those orders, and the photos and slips those point to.
// Cards a deleted user bought go too, because a card whose order is gone would be back on sale.
static async Task PurgeDeletedAccountsAsync(IConfiguration config, IWebHostEnvironment env, ILogger logger)
{
    await using var connection = new SqlConnection(config.GetConnectionString("DefaultConnection"));
    await connection.OpenAsync();
    await using var transaction = (SqlTransaction)await connection.BeginTransactionAsync();

    await using var command = new SqlCommand(
        """
        SET NOCOUNT ON;
        DECLARE @users TABLE (user_id INT PRIMARY KEY);
        INSERT INTO @users SELECT user_id FROM USERS WHERE deleted_at < DATEADD(day, -30, SYSUTCDATETIME());

        DECLARE @cards TABLE (card_id INT PRIMARY KEY);
        INSERT INTO @cards
            SELECT card_id FROM CARDS WHERE seller_id IN (SELECT user_id FROM @users)
            UNION
            SELECT card_id FROM ORDERS WHERE user_id IN (SELECT user_id FROM @users);

        DELETE FROM REVIEWS
        WHERE buyer_id IN (SELECT user_id FROM @users)
           OR order_id IN (SELECT order_id FROM ORDERS WHERE card_id IN (SELECT card_id FROM @cards));
        DELETE FROM ORDERS OUTPUT N'slip', DELETED.payment_slip WHERE card_id IN (SELECT card_id FROM @cards);
        DELETE FROM CARDS OUTPUT N'picture', DELETED.card_picture WHERE card_id IN (SELECT card_id FROM @cards);
        DELETE FROM USERS OUTPUT N'user', DELETED.username WHERE user_id IN (SELECT user_id FROM @users);
        """,
        connection,
        transaction);

    var removed = new List<(string Kind, string? Value)>();
    await using (var reader = await command.ExecuteReaderAsync())
    {
        do
        {
            while (await reader.ReadAsync())
            {
                removed.Add((reader.GetString(0), reader.IsDBNull(1) ? null : reader.GetString(1)));
            }
        } while (await reader.NextResultAsync());
    }
    await transaction.CommitAsync();

    foreach (var (kind, value) in removed)
    {
        if (kind == "slip") DeleteSlip(value, env);
        if (kind == "picture") DeletePicture(value, env);
    }
    var users = removed.Where((item) => item.Kind == "user").Select((item) => item.Value).ToList();
    if (users.Count > 0)
    {
        logger.LogInformation("Removed {Count} deleted accounts: {Usernames}", users.Count, string.Join(", ", users));
    }
}

static bool IsValidEmail(string email) =>
    System.Net.Mail.MailAddress.TryCreate(email, out var parsed) && parsed.Address == email;

// Everything about a user except the password hash.
static async Task<UserProfile?> LoadProfileAsync(SqlConnection connection, int userId)
{
    await using var command = new SqlCommand(
        "SELECT user_id, name, surname, username, email, phone_number, address FROM USERS WHERE user_id = @userId AND deleted_at IS NULL",
        connection);
    command.Parameters.AddWithValue("@userId", userId);

    await using var reader = await command.ExecuteReaderAsync();
    if (!await reader.ReadAsync())
    {
        return null;
    }

    return new UserProfile(
        reader.GetInt32(0),
        reader.GetString(1),
        reader.GetString(2),
        reader.GetString(3),
        reader.GetString(4),
        reader.IsDBNull(5) ? null : reader.GetString(5),
        reader.IsDBNull(6) ? null : reader.GetString(6));
}

record UserProfile(
    int UserId,
    string Name,
    string Surname,
    string Username,
    string Email,
    string? PhoneNumber,
    string? Address);

record CatalogCard(
    int CatalogId,
    string CardName,
    string? SetName,
    string? CardNumber,
    string CardType,
    string Rarity,
    string? CardStage,
    string? CardElement,
    string? CardPicture,
    decimal? ReferencePrice);

// One listing as the pages show it. CardPicture is the seller's photo, or the catalog picture without one.
record CardListing(
    int CardId,
    int CatalogId,
    string CardName,
    string SellerName,
    string CardType,
    string Rarity,
    decimal? ReferencePrice,
    decimal CardPrice,
    string? CardStage,
    string? CardElement,
    string? CardPicture,
    string? CardDescription,
    bool Sold); // someone has ordered it

record UpdateListingRequest(decimal? CardPrice, string? CardDescription);

// One order. PaymentSlip is the address of the slip picture, which only the buyer and seller can open.
record Order(int OrderId, int CardId, string BuyerName, string OrderStatus, decimal OrderPrice, string? PaymentSlip);

// An order for one of the seller's cards, with what the seller needs to send it.
record Sale(int OrderId, int CardId, string BuyerName, string OrderStatus, decimal OrderPrice, string? PaymentSlip, BuyerContact Buyer);

record BuyerContact(string Name, string Surname, string Email, string? PhoneNumber, string? Address);

record Review(int ReviewId, int OrderId, string BuyerName, string ReviewStatus, string Comment);

record SellerReview(Review Review, CardListing Card);

record AddReviewRequest(string? Comment);

record LoginRequest(string? Username, string? Password);

// What other users may see about a seller, so buyers can contact them. The address stays private.
record PublicProfile(int UserId, string Name, string Surname, string Username, string Email, string? PhoneNumber);

record UpdateProfileRequest(string? Name, string? Surname, string? Email, string? PhoneNumber, string? Address);

record DeleteAccountRequest(string? Password);

record RegisterRequest(
    string? Name,
    string? Surname,
    string? Username,
    string? Email,
    string? Password,
    string? PhoneNumber,
    string? Address);

record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}
