using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Vaulty.Graph.Onboarding;

/// <summary>A certificate Vaulty generated for one tenant's app registration.</summary>
/// <param name="Pfx">Certificate with private key (PKCS#12, no password); stored only in the encrypted secrets store.</param>
/// <param name="PublicCertificate">DER of the certificate without key; this goes into the app registration.</param>
public sealed record TenantCertificateMaterial(byte[] Pfx, byte[] PublicCertificate, string Thumbprint, DateTimeOffset NotBefore,
    DateTimeOffset NotAfter)
{
    public string PublicCertificateBase64 => Convert.ToBase64String(PublicCertificate);
}

public static class TenantCertificate
{
    public static readonly TimeSpan DefaultValidity = TimeSpan.FromDays(730);

    /// <summary>Creates a self-signed RSA 3072 / SHA-256 certificate for client authentication.</summary>
    public static TenantCertificateMaterial Create(string tenantLabel, TimeProvider? clock = null, TimeSpan? validity = null)
    {
        var now = (clock ?? TimeProvider.System).GetUtcNow();
        using var rsa = RSA.Create(3072);
        var safe = new string(tenantLabel.Where(c => char.IsLetterOrDigit(c) || c is ' ' or '-' or '.').ToArray()).Trim();
        var request = new CertificateRequest($"CN=Vaulty {(safe.Length == 0 ? "tenant" : safe)}", rsa, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.2")], critical: false));
        // Whole seconds: a certificate stores its validity in seconds, and Microsoft refuses an app key whose end date is
        // later than the certificate's, so the script, the database and the certificate must carry the same instant.
        var notBefore = WholeSeconds(now.AddMinutes(-10));
        var notAfter = WholeSeconds(now + (validity ?? DefaultValidity));
        using var certificate = request.CreateSelfSigned(notBefore, notAfter);
        return new TenantCertificateMaterial(certificate.Export(X509ContentType.Pkcs12), certificate.Export(X509ContentType.Cert),
            certificate.Thumbprint, notBefore, notAfter);
    }

    private static DateTimeOffset WholeSeconds(DateTimeOffset value) => new(value.Ticks - value.Ticks % TimeSpan.TicksPerSecond, value.Offset);

    public static X509Certificate2 Load(ReadOnlySpan<byte> pfx) =>
        X509CertificateLoader.LoadPkcs12(pfx, null, X509KeyStorageFlags.EphemeralKeySet);

    /// <summary>The material of a stored certificate (the public part is derived from the PKCS#12 with the key).</summary>
    public static TenantCertificateMaterial FromPfx(ReadOnlySpan<byte> pfx)
    {
        using var certificate = Load(pfx);
        return new TenantCertificateMaterial(pfx.ToArray(), certificate.Export(X509ContentType.Cert), certificate.Thumbprint,
            new DateTimeOffset(certificate.NotBefore.ToUniversalTime(), TimeSpan.Zero), new DateTimeOffset(certificate.NotAfter.ToUniversalTime(), TimeSpan.Zero));
    }
}

/// <summary>
/// The PowerShell script (Microsoft Graph PowerShell SDK) that creates the "Vaulty" app registration in the customer's
/// tenant, attaches the generated certificate, grants the application permissions (admin consent) and prints the tenant
/// id and client id to enter in Vaulty. Plus the same steps for people who do not want to run a script.
/// </summary>
public static class OnboardingScript
{
    public const string GraphAppId = "00000003-0000-0000-c000-000000000000";

    public static string PowerShell(string appName, TenantCertificateMaterial certificate, bool includeRestore)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        var permissions = GraphPermissions.All.Where(p => includeRestore || !p.ForRestore).Select(p => $"    '{p.Name}'");
        var sb = new StringBuilder();
        sb.AppendLine("#Requires -Version 7.2");
        sb.AppendLine("# Creates the app registration Vaulty uses to back up this Microsoft 365 tenant.");
        sb.AppendLine("# Run as a Global Administrator of the tenant. Nothing is sent to Vaulty; copy the two ids at the end into Vaulty.");
        sb.AppendLine("# Requires the Microsoft Graph PowerShell SDK: Install-Module Microsoft.Graph.Applications -Scope CurrentUser");
        sb.AppendLine("$ErrorActionPreference = 'Stop'");
        sb.AppendLine("if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Applications)) {");
        sb.AppendLine("    throw 'The Microsoft Graph PowerShell SDK is missing. Run: Install-Module Microsoft.Graph.Applications -Scope CurrentUser, then run this script again.'");
        sb.AppendLine("}");
        sb.AppendLine();
        sb.AppendLine($"$AppName = '{appName.Replace("'", "''", StringComparison.Ordinal)}'");
        sb.AppendLine($"$CertificateBase64 = '{certificate.PublicCertificateBase64}'");
        sb.AppendLine("# The end date comes from the certificate itself: Microsoft refuses a key end date later than the certificate's own.");
        sb.AppendLine("$CertificateNotAfter = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($CertificateBase64)).NotAfter.ToUniversalTime()");
        sb.AppendLine("$Permissions = @(");
        sb.AppendLine(string.Join(",\n", permissions));
        sb.AppendLine(")");
        sb.AppendLine();
        sb.AppendLine("Connect-MgGraph -Scopes 'Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All' -NoWelcome");
        sb.AppendLine("$TenantId = (Get-MgContext).TenantId");
        sb.AppendLine("# A second run must not create a second app registration.");
        sb.AppendLine("if (Get-MgApplication -Filter \"displayName eq '$($AppName.Replace(\"'\", \"''\"))'\") {");
        sb.AppendLine("    throw \"An app registration named '$AppName' already exists in this tenant. Remove it in Entra (App registrations), then run this script again.\"");
        sb.AppendLine("}");
        sb.AppendLine($"$Graph = Get-MgServicePrincipal -Filter \"appId eq '{GraphAppId}'\"");
        sb.AppendLine("$Roles = foreach ($name in $Permissions) {");
        sb.AppendLine("    $role = $Graph.AppRoles | Where-Object { $_.Value -eq $name -and $_.AllowedMemberTypes -contains 'Application' }");
        sb.AppendLine("    if (-not $role) { throw \"Microsoft Graph has no application permission named $name\" }");
        sb.AppendLine("    $role");
        sb.AppendLine("}");
        sb.AppendLine();
        sb.AppendLine("$App = New-MgApplication -DisplayName $AppName -SignInAudience 'AzureADMyOrg' `");
        sb.AppendLine($"    -RequiredResourceAccess @{{ ResourceAppId = '{GraphAppId}'; ResourceAccess = @($Roles | ForEach-Object {{ @{{ Id = $_.Id; Type = 'Role' }} }}) }} `");
        sb.AppendLine("    -KeyCredentials @(@{ Type = 'AsymmetricX509Cert'; Usage = 'Verify'; Key = [Convert]::FromBase64String($CertificateBase64);");
        sb.AppendLine("                         EndDateTime = $CertificateNotAfter; DisplayName = 'Vaulty' })");
        sb.AppendLine("$ServicePrincipal = New-MgServicePrincipal -AppId $App.AppId");
        sb.AppendLine();
        sb.AppendLine("# Admin consent: assign every application permission to the app's service principal.");
        sb.AppendLine("foreach ($role in $Roles) {");
        sb.AppendLine("    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipal.Id -PrincipalId $ServicePrincipal.Id `");
        sb.AppendLine("        -ResourceId $Graph.Id -AppRoleId $role.Id | Out-Null");
        sb.AppendLine("}");
        sb.AppendLine();
        sb.AppendLine("Write-Host ''");
        sb.AppendLine("Write-Host 'Enter these values in Vaulty:'");
        sb.AppendLine("Write-Host \"  Tenant ID: $TenantId\"");
        sb.AppendLine("Write-Host \"  Application ID: $($App.AppId)\"");
        sb.AppendLine("Write-Host ''");
        sb.AppendLine("Write-Host 'Microsoft can take a few minutes before the new app can sign in. Vaulty retries the permission check.'");
        return sb.ToString();
    }

    /// <summary>The same steps for the Entra admin center, for people who do not want to run a script.</summary>
    public static IReadOnlyList<string> ManualSteps(string appName, bool includeRestore)
    {
        var permissions = string.Join(", ", GraphPermissions.All.Where(p => includeRestore || !p.ForRestore).Select(p => p.Name));
        return
        [
            "Sign in to the Microsoft Entra admin center as a Global Administrator of the tenant.",
            $"Go to Identity > Applications > App registrations > New registration. Name: {appName}. Supported account types: this organizational directory only. No redirect URI. Register.",
            "Copy the Application (client) ID and the Directory (tenant) ID from the overview; you enter them in Vaulty as Application ID and Tenant ID.",
            "Go to Certificates & secrets > Certificates > Upload certificate and upload the certificate file you downloaded from Vaulty. Do not create a client secret.",
            $"Go to API permissions > Add a permission > Microsoft Graph > Application permissions and add: {permissions}.",
            "Select Grant admin consent for the organization and confirm. Every permission must show a green check.",
            "Return to Vaulty, enter the tenant ID and application ID, and run the permission check.",
        ];
    }

    public static string CertificatePem(TenantCertificateMaterial certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return new string(PemEncoding.Write("CERTIFICATE", certificate.PublicCertificate));
    }
}
