function Invoke-DeflateAndEncode {
    param (
        [Parameter(Mandatory)]
        $payload
    )

    $iStream = [IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($payload))
    $oStream = New-Object System.IO.MemoryStream
    $compressedStream =  New-Object System.IO.Compression.DeflateStream($oStream, [System.IO.Compression.CompressionMode]::Compress)
    $iStream.CopyTo($compressedStream)
    $compressedStream.Close()
    $oStream.Close()
    [Convert]::ToBase64String($oStream.ToArray())
}

function Get-AllAzureADAWSApplicationSAMLTokens {
    
    param (
        [Parameter(Mandatory)]
        $tenantId,
        [Parameter(Mandatory)]
        $servicePrincipals,
        [Parameter(Mandatory)]
        $estsAuthPersistentCookie
    )
    
    $returnItems = [System.Collections.ArrayList]@()

    $servicePrincipals | ForEach-Object {
        if ($_.Homepage -Match "https://signin.aws.amazon.com/saml") {
            if ($_.ServicePrincipalNames.Count -lt 1) {
                continue
            }
            $issuer = $_.ServicePrincipalNames[0]
            $samlInfo = Get-AzureADAWSApplicationSAMLToken $tenantId $issuer $estsAuthPersistentCookie
            $samlInfo['Name'] = $_.DisplayName
            $null = $returnItems.Add($samlInfo)
        }
    }

    return ,$returnItems
}

function Get-SAMLResponseData {
    param (
        [Parameter(Mandatory)]
        $b64SAMLResponse
    )

    $decodedResponse = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64SAMLResponse))

    # This is super flimsy, figure out a better way to do this
    $doc = [xml]$decodedResponse
    $roleInfo = $doc.ChildNodes[0].Assertion.AttributeStatement.Attribute | Where-Object {$_.Name -eq "https://aws.amazon.com/SAML/Attributes/Role"}

    $roleArn = $roleInfo.AttributeValue.split(',')[0]
    $principalArn = $roleInfo.AttributeValue.split(',')[1]

    $returnDictionary = @{}
    $returnDictionary['role-arn'] = $roleArn
    $returnDictionary['principal-arn'] = $principalArn
    $returnDictionary['saml-assertion'] = $b64SAMLResponse

    $returnDictionary

}

function Get-AzureADAWSApplicationSAMLToken {

    param (
        [Parameter(Mandatory)]
        $tenantId,
        [Parameter(Mandatory)]
        $issuerID,
        [Parameter(Mandatory)]
        $estsAuthPersistentCookie
        
    )

    $BASEURL = "https://login.microsoftonline.com/$tenantId/saml2?SAMLRequest="
    $COOKIENAME = "ESTSAUTHPERSISTENT"
    $DOMAIN = ".login.microsoftonline.com"

    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $cookie = New-Object System.Net.Cookie

    $cookie.Name = $COOKIENAME
    $cookie.Value = $estsAuthPersistentCookie
    $cookie.Domain = $DOMAIN

    $session.Cookies.Add($cookie)

    # Get a timestamp for the issue instant
    $time = Get-Date
    $time = $time.ToUniversalTime().ToString("yyyy-MM-ddThh:mm:ss.fff") + "z"

    # Generate the SAML Request
    $samlRequest = "<samlp:AuthnRequest xmlns=`"urn:oasis:names:tc:SAML:2.0:metadata`" ID=`"F84D888AA3B44C1B844375A4E8210D9E`" Version=`"2.0`" IssueInstant=`"$time`" IsPassive=`"true`" AssertionConsumerServiceURL=`"https://signin.aws.amazon.com/saml`" xmlns:samlp=`"urn:oasis:names:tc:SAML:2.0:protocol`" ForceAuthn=`"false`"><Issuer xmlns=`"urn:oasis:names:tc:SAML:2.0:assertion`">$issuer</Issuer></samlp:AuthnRequest>"
  
    # Convert the SAML request into a DEFLATE compressed and base64 encoded payload
    $encodedPayload = Invoke-DeflateAndEncode($samlRequest)      

    # Generate the URL
    $urlRequest = $baseUrl + [System.Web.HTTPUtility]::UrlEncode($encodedPayload)

    $response = Invoke-WebRequest -Uri $urlRequest -WebSession $session
    $samlResponse = $response.InputFields[0].value

    Get-SAMLResponseData $samlResponse

}

function Invoke-LoginToAllAvailableAWSAccounts {
    param (
        [Parameter(Mandatory)]
        $tenantId,
        [Parameter(Mandatory)]
        $servicePrincipals,
        [Parameter(Mandatory)]
        $estsAuthPersistentCookie
    )

    $samlAssertions = Get-AllAzureADAWSApplicationSAMLTokens $tenantId $servicePrincipals $estsAuthPersistentCookie

    $returnItems = [System.Collections.ArrayList]@()

    $samlAssertions | ForEach-Object {
        $roleArn = $_['role-arn']
        $principalArn = $_['principal-arn']
        $samlAssertion = $_['saml-assertion']
        $duration = 3600

        $awsSamlResponse = Use-STSRoleWithSAML -RoleArn $roleArn -PrincipalArn $principalArn -SAMLAssertion $samlAssertion -DurationInSeconds $duration
        $null = $returnItems.Add($awsSamlResponse)
    }

    return ,$returnItems

}

