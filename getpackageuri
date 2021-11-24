#use app to query api, followed https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api-hello-world?view=o365-worldwide
$appSecret="<app secret>"
$appId ="<app id>"
$tenantId ="<tenant id>"
$subscription="<subscription id>"
$LogicAppsUrl="<logic app url>"

#get token into header
$resourceAppIdUri = 'https://api.securitycenter.microsoft.com'
$oAuthUri = "https://login.microsoftonline.com/$TenantId/oauth2/token"
$authBody = [Ordered] @{
     resource = "$resourceAppIdUri"
     client_id = "$appId"
     client_secret = "$appSecret"
     grant_type = 'client_credentials'
}
$authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
$token = $authResponse.access_token
Out-File -FilePath "./Latest-token.txt" -InputObject $token
return $token
$headers = @{
    'Content-Type' = 'application/json'
    Accept = 'application/json'
    Authorization = "Bearer $token"
}
#Wait for token to be accepted by MDE
Start-Sleep -Seconds 30
#list machines
$machines=Invoke-RestMethod -Method Get -uri "https://api.securitycenter.microsoft.com/api/machines" -Headers $headers  

#json for the body of the automated investigation request
$body = @"
{
     "Comment": "Automated collection from ps"
}
"@
$packages=@{}
$machines= $machines | where {$_.value.osPlatform -eq "Windows10"}
#get over the list of machines and ask for investigation package, it only works on Win 10 over 1703
foreach ($machine in $machines.value){
    if ($machine.osPlatform -ne "Windows10"){
        break
        }
    $machineid=$machine.id
    $packagestatus=$null
    try{
        $packagestatus=Invoke-RestMethod -Method post -uri "https://api.securitycenter.microsoft.com/api/machines/$machineid/collectInvestigationPackage" -Headers $headers -Body $body 
        $packages.Add($machine.computerDnsName,$packagestatus)

        }
    catch
        {
        Write-output "failed to collect" $machine.computerDnsName
        }
#wait to acknowledge for api limits   
 Start-Sleep -Seconds 30 
    }
$SASURIs=@{}
#go over collected packages and get the SASURI, then call the logic app
foreach ($package in $packages.GetEnumerator()){
    $SASURI=$null
    $packageid=$package.value.id
    $SASURI=Invoke-RestMethod -Method get -uri "https://api.securitycenter.microsoft.com/api/machineactions/$packageid/getPackageUri" -Headers $headers 
    $SASURIs.Add($package.Value.computerDnsName,$SASURI)   
   #get as object the uri and token for the blob SAS
    $url,$SAStoken,$SAStoken=$null
    $url=$($SASURI.value)
    $SAStoken=$SASURI.value.Split("?",2)[1]
    $sasobject=New-Object -TypeName psobject
    $sasobject | Add-Member -MemberType NoteProperty -Name URL -Value "$URL"
    $sasobject | Add-Member -MemberType NoteProperty -Name SASToken -Value "$SAStoken"
    $sasobject | Add-Member -MemberType NoteProperty -Name Machinename -Value $package.Key
    $sasobjectjson=ConvertTo-Json $sasobject
    #call the http trigger in the logic app
    $LogicAppInfo = Invoke-WebRequest -Uri $LogicAppsUrl -Headers @{
    "Content-Type" = "application/json"
    } -Method Post -Body $sasobjectjson  -UseBasicParsing
    Start-Sleep -Seconds 15
    }
