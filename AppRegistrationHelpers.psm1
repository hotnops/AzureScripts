function Get-AzureADAppRegistrationGraphPermissions
{
    param(
        [Parameter(Mandatory,
        ParameterSetName="all")]
        [switch]
        $all,

        [Parameter(Mandatory,
        ParameterSetName="oneapp")]
        [string]
        $appId
    )

    if ($all)
    {
        $apps = Get-AzureADApplication -All $true
    }
    else {
        $apps = $()
        $apps += Get-AzureADApplication -ObjectId $appId
    }

    $sps = Get-AzureADServicePrincipal -All $true

    $returnVal = @{}

    $apps | ForEach-Object {
        $appMap = @{}
        $app = $_
        $app.RequiredResourceAccess | ForEach-Object {
            $resourceAppId = $_.ResourceAppId
            $servicePrincipal = $sps | Where-Object {$_.AppId -eq $resourceAppId}

            $appMap[$servicePrincipal.DisplayName] = @{'Application' = [System.Collections.ArrayList]@(); 'Delegated' = [System.Collections.ArrayList]@()}

            $_.ResourceAccess | ForEach-Object {
                $resourceId = $_.Id
                if ($_.Type -eq "Role") {
                    
                    $role = $servicePrincipal.AppRoles | Where-Object {$_.Id -eq $resourceId}
                    $null = $appMap[$servicePrincipal.DisplayName]['Application'].Add($role.Value)
                }
                else
                {
                    $role = $servicePrincipal.OAuth2Permissions | Where-Object {$_.Id -eq $resourceId}
                    $null = $appMap[$servicePrincipal.DisplayName]['Delegated'].Add($role.Value)
                }
            }
        }

        if ($appMap.Count -gt 0)
        {
            $key = [string]::Format("{0} ({1})", $_.AppId, $_.DisplayName)
            $returnVal[$key] = $appMap
        }
    }

    $returnVal
}

function Get-AzureADGraphTokenFromClientSecret {
    param (
        [Parameter(Mandatory)]
        [string]$TenantId,
        [Parameter(Mandatory)]
        [string]$ClientId,
        [Parameter(Mandatory)]
        [string]$ClientSecret
    )

    $grant_type = "client_credentials"
    $resource = "https://graph.microsoft.com"
    $contentType = 'application/x-www-form-urlencoded'

    $body = @{grant_type=$grant_type
        client_id=$clientID
        client_secret=$clientSecret
        scope="https://graph.microsoft.com/.default"
        resource=$resource}

    $resp = Invoke-WebRequest -Uri https://login.microsoftonline.com/$($tenantId)/oauth2/token -Method Post -Body $body -ContentType $contentType -UseBasicParsing
    $oauth_resp = $resp.Content | ConvertFrom-Json
    $oauth_resp.access_token    
}

function Get-UniqueDomains{
    param (
        [Parameter(Mandatory)]
        $urls
    )

    $domains = [System.Collection.ArrayList]@()

    $urls | ForEach-Object {
        $domain = Get-DomainFromUrl $_
        $domains.Add($domain)
    }

    $urls | Sort-Object | Get-Unique
}

function Get-UnregisteredDomains{
    param (
        [Parameter(Mandatory)]
        $domains
    )

    $url = "https://rdap.verisign.com/com/v1/domain/"
    $unregisteredDomains = [System.Collections.ArrayList]@()

    $domains | ForEach-Object {
        $domainUrl = $url + $_
        $resp = try{
            Invoke-WebRequest -Uri $domainUrl
        }
        catch [System.Net.WebException] 
        {
            $_.Exception.Response
        }
        if ($resp.StatusCode.value__ -eq 404)
        {
            $null = $unregisteredDomains.Add($_)
        }
    }

    $unregisteredDomains
}

function Get-VulnerableReplyURLs{
    param (
        [Parameter(Mandatory)]
        $sps
    )

    $replyUrls = [System.Collections.ArrayList]@()

    # Get all reply urls
    $sps | ForEach-Object {
        $sp = $_
        $sp.ReplyUrls | ForEach-Object{
            $uri = [System.Uri]$_
            if ($uri.Scheme -eq "https") {
                if (($uri.Host.ToCharArray() | Where-Object {$_ -eq '.'} | Measure-Object).Count -gt 1) {
                    $parts = $uri.Host.split('.')
                    $domain = $parts[-2] + "." + $parts[-1]
                    $null = $replyUrls.Add($domain)
                } 
                elseif (($uri.Host.ToCharArray() | Where-Object {$_ -eq '.'} | Measure-Object).Count -eq 1) {
                    $null = $replyUrls.Add($uri.Host)
                }
            }
        }
    }

    # Sort and get unique
    $domains = $replyUrls | Sort-Object | Get-Unique

    Get-UnregisteredDomains($domains)
}