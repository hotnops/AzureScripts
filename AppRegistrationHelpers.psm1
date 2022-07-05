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